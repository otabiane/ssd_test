Install Pipenv
```
pip install pipenv
```

To activate the virtual environment:
```
pipenv shell
```

Lock dependencies:
```
pipenv install
```

To launch the database:
```
docker run --name health-postgres \
    -e POSTGRES_USER=health_user \
    -e POSTGRES_PASSWORD=your_secure_password \
    -e POSTGRES_DB=health_db \
    -p 5433:5432 \
    -d postgres

docker run --name logs-postgres \
    -e POSTGRES_USER=logs_user \
    -e POSTGRES_PASSWORD=your_secure_password \
    -e POSTGRES_DB=logs_db \
    -p 5434:5432 \
    -d postgres
```

Launch the application
```
python3 manage.py makemigrations
python3 manage.py makemigrations app
python3 manage.py makemigrations logs
python3 manage.py migrate
python3 manage.py migrate --database=default
python3 manage.py migrate --database=logs
python3 manage.py runserver
```