from flask import Flask, render_template, request

import des

app = Flask(__name__)

@app.get("/")
def index() -> ...:
    return render_template("index.jinja2")


@app.post("/encrypt")
def encrypt_text() -> ...:
    if "key" not in request.form or "data" not in request.form:
        return index()

    key = request.form["key"].lower().strip()
    if len(key) != 16 or not all(ch in "0123456789abcdef" for ch in key):
        return index()

    key = int(key, 16)
    data_to_encrypt = request.form["data"].encode("utf8")
    encrypted = des.ecb_encrypt(data_to_encrypt, key)

    return render_template("index.jinja2", encrypted_data=encrypted.hex())


@app.post("/decrypt")
def decrypt_text() -> ...:
    if "key" not in request.form or "data" not in request.form:
        return index()

    key = request.form["key"].lower().strip()
    if len(key) != 16 or not all(ch in "0123456789abcdef" for ch in key):
        return index()

    key = int(key, 16)
    data_to_decrypt = bytes.fromhex(request.form["data"])
    decrypted = des.ecb_decrypt(data_to_decrypt, key)

    return render_template("index.jinja2", decrypted_data=decrypted.decode("utf8"))


if __name__ == "__main__":
    app.jinja_env.auto_reload = True
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.run(host="127.0.0.1", port=9999, use_reloader=True, reloader_type="watchdog")
