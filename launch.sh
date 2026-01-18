#!/bin/bash

set -e

echo "Configuring databases..."

if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start/install Docker first."
    exit 1
fi

# function to create/start a container
launch_db() {
    NAME=$1
    USER=$2
    DB=$3
    PORT=$4

    # check if container exists
    if [ "$(docker ps -aq -f name=^/${NAME}$)" ]; then
        # check if it is running
        if [ "$(docker ps -q -f name=^/${NAME}$)" ]; then
            echo "$NAME is already running."
        else
            echo "Starting existing container $NAME..."
            docker start $NAME
        fi
    else
        echo "Creating new container $NAME..."
        docker run --name $NAME \
            -e POSTGRES_USER=$USER \
            -e POSTGRES_PASSWORD=your_secure_password \
            -e POSTGRES_DB=$DB \
            -p $PORT:5432 \
            -d postgres
    fi
}

# launch db
launch_db "health-postgres" "health_user" "health_db" "5433"
launch_db "logs-postgres" "logs_user" "logs_db" "5434"

sleep 3

cd health/

echo "configuring environment..."

CMD="python3"

if [[ -n "$VIRTUAL_ENV" ]]; then
    echo "Active Virtual Environment detected ($VIRTUAL_ENV)."
    CMD="python3"
elif [ -f "Pipfile" ] && command -v pipenv &> /dev/null; then
    echo "Pipfile found. Using 'pipenv run'..."
    pipenv install 
    CMD="pipenv run python3"
else
    echo "No virtualenv or Pipenv detected. Using system python3."
    CMD="python3"
fi

echo "Running mitigations"

echo "Making migrations..."
$CMD manage.py makemigrations
$CMD manage.py makemigrations app
$CMD manage.py makemigrations logs

echo "Applying migrations..."
$CMD manage.py migrate
$CMD manage.py migrate --database=default
$CMD manage.py migrate --database=logs

echo "Staring server..." 
$CMD manage.py runserver
echo "App available at http://localhost:8000"