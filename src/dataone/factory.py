class AuthFactory:

    _registry = {
        "flask": "dataone.adapters.flask.FlaskAuthAdapter",
        "fastapi": "dataone.adapters.fastapi.FastAPIAuthAdapter",
        "starlette": "dataone.adapters.fastapi.FastAPIAuthAdapter",
    }

    @classmethod
    def create_client(cls, framework: str, config: dict):
        import_path = cls._registry.get(framework.lower())
        if not import_path:
            raise ValueError(f"Unsupported framework: {framework}")
            
        module_path, class_name = import_path.rsplit(".", 1)
        module = __import__(module_path, fromlist=[class_name])
        AdapterClass = getattr(module, class_name)
        
        return AdapterClass(config=config)