from flask import Flask
from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "super_secret_key_2026_change_this"

    app.register_blueprint(main_bp)
    app.register_blueprint(proxy_bp)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)