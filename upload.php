<?php
session_start();

$upload_dir = 'uploads/';
$max_file_size = 5 * 1024 * 1024;
$allowed_extensions = ['png'];
$allowed_mime_types = ['image/png'];

define('MAX_DELETES_PER_MINUTE', 3);
define('DELETE_COOLDOWN_SECONDS', 30);

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0755, true);
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!isset($_SESSION['delete_count'])) {
    $_SESSION['delete_count'] = 0;
    $_SESSION['delete_window_start'] = time();
}

function log_security_event($message, $level = 'WARNING') {
    $log_file = 'security.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $session = session_id();
    $log_entry = "[$timestamp] [$level] IP: $ip - Session: $session - $message\n";
    file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
}

function validate_png($file_path) {
    $image_info = @getimagesize($file_path);
    if ($image_info === false || $image_info[2] !== IMAGETYPE_PNG) {
        return false;
    }
    
    $handle = fopen($file_path, 'rb');
    $header = fread($handle, 8);
    fclose($handle);
    
    $png_signature = "\x89PNG\r\n\x1a\n";
    if ($header !== $png_signature) {
        return false;
    }
    
    return true;
}

function scan_png_chunks($file_path) {
    $handle = fopen($file_path, 'rb');
    
    $header = fread($handle, 8);
    
    $malicious_chunks = [];
    $suspicious_keywords = ['<?php', 'eval', 'base64_decode', 'fsockopen', 'shell_exec', 'system', 'exec', 'passthru', '`'];
    
    while (!feof($handle)) {
        $chunk_data = fread($handle, 4);
        if (strlen($chunk_data) < 4) break;
        
        $chunk_length = unpack('N', $chunk_data)[1];
        
        $chunk_type = fread($handle, 4);
        if (strlen($chunk_type) < 4) break;
        
        if ($chunk_length > 0) {
            $chunk_content = fread($handle, $chunk_length);
            
            if (in_array($chunk_type, ['tEXt', 'zTXt', 'iTXt'])) {
                foreach ($suspicious_keywords as $keyword) {
                    if (stripos($chunk_content, $keyword) !== false) {
                        $malicious_chunks[] = [
                            'type' => $chunk_type,
                            'content' => substr($chunk_content, 0, 100) . '...'
                        ];
                        break;
                    }
                }
            }
            
            fread($handle, 4);
        } else {
            fread($handle, 4); 
        }
    }
    
    fclose($handle);
    return $malicious_chunks;
}

function clean_png_metadata($file_path) {
    $img = imagecreatefrompng($file_path);
    if (!$img) return false;
    
    $new_img = imagecreatetruecolor(imagesx($img), imagesy($img));
    imagecopy($new_img, $img, 0, 0, 0, 0, imagesx($img), imagesy($img));
    
    $temp_file = tempnam(sys_get_temp_dir(), 'png_');
    imagepng($new_img, $temp_file, 9);
    
    imagedestroy($img);
    imagedestroy($new_img);
    
    return $temp_file;
}

$message = '';
$message_type = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        log_security_event("Intento de subida sin CSRF válido", 'CRITICAL');
        die("Error de seguridad: Token inválido");
    }
    
    $file = $_FILES['image'];
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $message = 'Error en la subida del archivo';
        $message_type = 'error';
    } elseif ($file['size'] > $max_file_size) {
        $message = 'El archivo es demasiado grande (máximo 5MB)';
        $message_type = 'error';
    } else {
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, $allowed_extensions)) {
            $message = 'Solo se permiten archivos PNG';
            $message_type = 'error';
        } else {
            $new_filename = uniqid() . '_' . bin2hex(random_bytes(8)) . '.png';
            $upload_path = $upload_dir . $new_filename;
            
            if (move_uploaded_file($file['tmp_name'], $upload_path)) {
                if (!validate_png($upload_path)) {
                    unlink($upload_path);
                    $message = 'El archivo no es un PNG válido';
                    $message_type = 'error';
                } 
                else {
                    $malicious = scan_png_chunks($upload_path);
                    if (!empty($malicious)) {
                        log_security_event("Intento de subir PNG con chunks maliciosos: " . implode(', ', array_column($malicious, 'type')));
                        
                        unlink($upload_path);
                        $message = 'Se detectó contenido malicioso en la imagen';
                        $message_type = 'error';
                        
                        $clean_file = clean_png_metadata($upload_path);
                        if ($clean_file) {
                            unlink($upload_path);
                            rename($clean_file, $upload_path);
                            $message = 'Imagen subida y limpiada de metadatos sospechosos';
                            $message_type = 'success';
                            
                            log_security_event("PNG malicioso limpiado automáticamente", 'INFO');
                        }
                    } else {
                        $message = 'Imagen subida exitosamente';
                        $message_type = 'success';
                        log_security_event("Archivo subido correctamente: $new_filename", 'INFO');
                    }
                }
            } else {
                $message = 'Error al guardar el archivo';
                $message_type = 'error';
                log_security_event("Error al guardar archivo", 'ERROR');
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete'])) {
    
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        log_security_event("Intento de eliminación sin CSRF válido", 'CRITICAL');
        die("Error de seguridad: Token inválido");
    }
    
    $current_time = time();
    
    if ($current_time - $_SESSION['delete_window_start'] > 60) {
        $_SESSION['delete_count'] = 0;
        $_SESSION['delete_window_start'] = $current_time;
    }
    
    if ($_SESSION['delete_count'] >= MAX_DELETES_PER_MINUTE) {
        $wait_time = 60 - ($current_time - $_SESSION['delete_window_start']);
        log_security_event("Rate limit excedido. Espera: {$wait_time}s", 'WARNING');
        die("Demasiadas eliminaciones. Espera $wait_time segundos.");
    }
    
    $file_to_delete = $upload_dir . basename($_POST['delete']);
    
    if (!file_exists($file_to_delete) || strpos(realpath($file_to_delete), realpath($upload_dir)) !== 0) {
        log_security_event("Intento de eliminar archivo inválido: " . $_POST['delete'], 'CRITICAL');
        die("Archivo no válido");
    }
    
    if (!isset($_POST['confirm']) || $_POST['confirm'] !== 'yes') {
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Confirmar eliminación</title>
            <style>
                body { font-family: Arial; background: #f0f0f0; padding: 50px; }
                .confirm-box { background: white; padding: 30px; border-radius: 10px; max-width: 500px; margin: auto; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
                .warning { color: #721c24; background: #f8d7da; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                button { padding: 10px 20px; margin: 5px; border: none; border-radius: 5px; cursor: pointer; }
                .btn-danger { background: #dc3545; color: white; }
                .btn-secondary { background: #6c757d; color: white; }
            </style>
        </head>
        <body>
            <div class="confirm-box">
                <h2>Confirmar eliminación</h2>
                <div class="warning">
                    <strong>Archivo:</strong> <?php echo htmlspecialchars($_POST['delete']); ?><br>
                    <strong>Tamaño:</strong> <?php 
                        $size = filesize($upload_dir . $_POST['delete']);
                        echo $size < 1024 ? $size . ' B' : round($size/1024, 2) . ' KB';
                    ?><br>
                    <strong>Fecha:</strong> <?php echo date('Y-m-d H:i:s', filemtime($upload_dir . $_POST['delete'])); ?>
                </div>
                <p>¿Estás seguro de que quieres eliminar este archivo?</p>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="hidden" name="delete" value="<?php echo htmlspecialchars($_POST['delete']); ?>">
                    <input type="hidden" name="confirm" value="yes">
                    <button type="submit" class="btn-danger">Sí, eliminar permanentemente</button>
                    <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="btn-secondary" style="text-decoration: none; display: inline-block; padding: 10px 20px;">Cancelar</a>
                </form>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    
    if (unlink($file_to_delete)) {
        $_SESSION['delete_count']++;
        log_security_event("Archivo eliminado correctamente: " . $_POST['delete'], 'INFO');
    } else {
        log_security_event("Error al eliminar archivo: " . $_POST['delete'], 'ERROR');
    }
    
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

$uploaded_files = glob($upload_dir . '*.png');
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Carga de PNG con Validaciones</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            padding: 30px;
            margin-bottom: 20px;
        }
        
        h1 {
            color: #333;
            margin-bottom: 20px;
            font-size: 24px;
        }
        
        .info-box {
            background: #f0f8ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .info-box h3 {
            color: #2196F3;
            margin-bottom: 10px;
        }
        
        .info-box ul {
            margin-left: 20px;
            color: #555;
        }
        
        .info-box li {
            margin: 5px 0;
        }
        
        .upload-form {
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        
        input[type="file"] {
            width: 100%;
            padding: 10px;
            border: 2px dashed #ddd;
            border-radius: 5px;
            background: #fafafa;
            cursor: pointer;
        }
        
        input[type="file"]:hover {
            border-color: #667eea;
        }
        
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: transform 0.2s;
        }
        
        button:hover {
            transform: translateY(-2px);
        }
        
        .message {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .files-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .file-item {
            background: #f8f9fa;
            border-radius: 5px;
            padding: 10px;
            text-align: center;
            border: 1px solid #dee2e6;
        }
        
        .file-item img {
            max-width: 100%;
            height: auto;
            border-radius: 3px;
            margin-bottom: 10px;
        }
        
        .file-name {
            font-size: 12px;
            color: #666;
            word-break: break-all;
        }
        
        .file-size {
            font-size: 11px;
            color: #999;
            margin-top: 5px;
        }
        
        .delete-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            margin-top: 8px;
        }
        
        .delete-btn:hover {
            background: #c82333;
        }
        
        .footer {
            text-align: center;
            color: white;
            margin-top: 20px;
            font-size: 14px;
        }
</style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Carga de Imágenes PNG</h1>
            
            <?php if ($message): ?>
                <div class="message <?php echo $message_type; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>
            
            <form class="upload-form" method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                
                <div class="form-group">
                    <label for="image">Seleccionar imagen PNG:</label>
                    <input type="file" name="image" id="image" accept=".png,image/png" required>
                </div>
                
                <button type="submit">Subir Imagen</button>
            </form>
            
            <h2>Imágenes Subidas (<?php echo count($uploaded_files); ?>)</h2>
            
            <?php if (count($uploaded_files) > 0): ?>
                <div class="files-grid">
                    <?php foreach ($uploaded_files as $file): 
                        $filename = basename($file);
                        $filesize = filesize($file);
                        $size_formatted = $filesize < 1024 ? $filesize . ' B' : 
                                         ($filesize < 1048576 ? round($filesize/1024, 2) . ' KB' : 
                                         round($filesize/1048576, 2) . ' MB');
                    ?>
                        <div class="file-item">
                            <img src="<?php echo $upload_dir . $filename; ?>" alt="PNG" onerror="this.src='data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiB2aWV3Qm94PSIwIDAgMjQgMjQiIGZpbGw9Im5vbmUiIHN0cm9rZT0iI2NjYyIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxyZWN0IHg9IjIiIHk9IjIiIHdpZHRoPSIyMCIgaGVpZ2h0PSIyMCIgcng9IjIiIHJ5PSIyIj48L3JlY3Q+PGNpcmNsZSBjeD0iOC41IiBjeT0iOC41IiByPSIxLjUiIGZpbGw9IiNjY2MiPjwvY2lyY2xlPjxwYXRoIGQ9Ik0yMSAxNUwxNiAxMCA1IDIxIj48L3BhdGg+PC9zdmc+'>">
                            <div class="file-name"><?php echo htmlspecialchars($filename); ?></div>
                            <div class="file-size"><?php echo $size_formatted; ?></div>
                            <form method="POST" style="display: inline;" onsubmit="return confirm('⚠️ ¿Eliminar imagen? Esta acción no se puede deshacer.');">
                                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                <input type="hidden" name="delete" value="<?php echo htmlspecialchars($filename); ?>">
                                <button type="submit" class="delete-btn">Eliminar</button>
                            </form>
                        </div>
                    <?php endforeach; ?>
                </div>
                
                <div style="margin-top: 20px; padding: 10px; background: #e9ecef; border-radius: 5px; text-align: center;">
                    <?php 
                    $remaining = MAX_DELETES_PER_MINUTE - $_SESSION['delete_count'];
                    if ($remaining < 0) $remaining = 0;
                    $reset_time = 60 - (time() - $_SESSION['delete_window_start']);
                    if ($reset_time < 0) $reset_time = 0;
                    ?>
                    <span style="color: #666;">Eliminaciones disponibles: </span>
                    <span style="font-weight: bold; <?php echo $remaining < 2 ? 'color: #dc3545;' : 'color: #28a745;'; ?>">
                        <?php echo $remaining; ?>/<?php echo MAX_DELETES_PER_MINUTE; ?>
                    </span>
                    <?php if ($remaining == 0): ?>
                        <span style="color: #666; margin-left: 10px;">(espera <?php echo $reset_time; ?>s)</span>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <p style="color: #999; text-align: center; padding: 20px;">No hay imágenes subidas aún</p>
            <?php endif; ?>
        </div>
        
        <div class="footer">
            <p>Entorno de pruebas KMJ Ciberseguridad - Sistema protegido</p>
        </div>
    </div>
</body>
</html>
