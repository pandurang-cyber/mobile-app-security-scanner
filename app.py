import os
from flask import Flask, render_template, request, jsonify
from androguard.core.bytecodes.apk import APK

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # Limit: 50MB

# High-risk permissions list
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Can read private SMS messages",
    "android.permission.SEND_SMS": "Can send SMS (Potential Toll Fraud)",
    "android.permission.RECORD_AUDIO": "Can record background audio",
    "android.permission.CAMERA": "Can access camera secretly",
    "android.permission.ACCESS_FINE_LOCATION": "Tracks precise GPS location",
    "android.permission.READ_CONTACTS": "Exfiltrates personal contact list",
    "android.permission.SYSTEM_ALERT_WINDOW": "Overlay attacks / Phishing risk"
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_apk():
    if 'apk_file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['apk_file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filepath = os.path.join('/tmp', file.filename)
    file.save(filepath)

    try:
        apk = APK(filepath)
        permissions = apk.get_permissions()
        
        # 1. Analyze Dangerous Permissions
        flagged_permissions = []
        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                flagged_permissions.append({
                    "permission": perm,
                    "risk": DANGEROUS_PERMISSIONS[perm]
                })

        # 2. Heuristic Obfuscation Check
        classes = apk.get_classes()
        short_names = [c for c in classes if len(c.split('/')[-1]) <= 2]
        obfuscation_ratio = (len(short_names) / len(classes)) * 100 if classes else 0
        is_obfuscated = obfuscation_ratio > 30.0

        os.remove(filepath)

        return jsonify({
            "app_name": apk.get_app_name(),
            "package_name": apk.get_package(),
            "total_permissions": len(permissions),
            "dangerous_permissions": flagged_permissions,
            "obfuscation_analysis": {
                "is_obfuscated": is_obfuscated,
                "obfuscation_score": f"{obfuscation_ratio:.1f}%",
                "details": "High ratio of short class names detected (e.g. ProGuard/R8)." if is_obfuscated else "Standard class naming detected."
            }
        })
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Failed to analyze APK: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
