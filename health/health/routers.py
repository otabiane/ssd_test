class LogRouter:
    log_models = {'LogEntry'}

    def db_for_read(self, model, **hints):
        """Attempts to read log models from the logs db."""
        if model._meta.model_name in self.log_models:
            return 'logs'
        return 'default'

    def db_for_write(self, model, **hints):
        """Attempts to write log models to the logs db."""
        if model._meta.model_name in self.log_models:
            return 'logs'
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations between objects in the same database.
        """
        # If both models are log models OR neither are log models, allow relation.
        db1 = self.db_for_write(obj1)
        db2 = self.db_for_write(obj2)
        if db1 == db2:
            return True
        return None # Do not allow relations across the two databases
    
    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """Ensure the LogEntry model only appears on the 'logs' database."""
        is_log_model = model_name in self.log_models

        if db == 'logs':
            # Only run log model migrations on the 'logs' database
            return is_log_model
        elif is_log_model:
            # Do NOT run log model migrations on the 'default' database
            return False 
        
        # All other models migrate to 'default'
        return db == 'default'