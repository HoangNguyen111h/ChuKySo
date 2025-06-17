from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

app = Flask(__name__)
app.secret_key = 'supersecret'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    files = os.listdir(UPLOAD_FOLDER)
    files = [f for f in files if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))]
    return render_template('index.html', files=files)

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    files = os.listdir(UPLOAD_FOLDER)
    files = [f for f in files if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))]
    return render_template('index.html', private_key=private_pem, public_key=public_pem, files=files)

@app.route('/sign_file', methods=['POST'])
def sign_file():
    file = request.files['file']
    private_key_text = request.form['private_key']
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    private_key = serialization.load_pem_private_key(private_key_text.encode(), password=None)
    with open(filepath, 'rb') as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    sig_path = os.path.join(UPLOAD_FOLDER, filename + '.sig')
    with open(sig_path, 'wb') as f:
        f.write(signature)

    pub_key = private_key.public_key()
    pub_path = os.path.join(UPLOAD_FOLDER, filename + '.pub')
    with open(pub_path, 'wb') as f:
        f.write(pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    flash('File đã được ký số thành công!')
    return redirect(url_for('index'))

@app.route('/verify_file', methods=['POST'])
def verify_file():
    file = request.files['file']
    sig_file = request.files['sig_file']
    public_key_text = request.form['public_key']

    data = file.read()
    signature = sig_file.read()
    public_key = serialization.load_pem_public_key(public_key_text.encode())

    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        flash('🟢 Chữ ký hợp lệ!')
    except Exception:
        flash('🔴 Chữ ký không hợp lệ!')

    return redirect(url_for('index'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True)
