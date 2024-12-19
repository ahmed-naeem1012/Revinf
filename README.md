# IP Data Retrieval and Storage System

This project is a web application built with FastAPI and Celery, designed to retrieve and store IP data from the ipdata.co API into a MySQL database.




https://github.com/kazimovzaman2/fastapi-celery-jwt/assets/92586852/9b9c9091-80f7-4eb9-8f65-db52601c5d06




## Features

- Fetches detailed information about an IP address from ipdata.co.
- Stores the fetched data in a MySQL database using Peewee ORM.
- Provides endpoints to create tasks for fetching IP data and to check the status of a task.
- Allows retrieval of saved IP data using task IDs.

## Prerequisites

Before running the application, ensure you have the following installed:

- Python 3.x
- pip (Python package manager)
- MySQL server
- RabbitMQ server (or another Celery-compatible message broker)

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/yourusername/ip-data-retrieval.git
   ```

2. Navigate to the project directory:
    ```
    cd ip-data-retrieval
    ```

3. Install dependencies:
    ```
    pip install -r app/requirements.txt
    ```

4. Set up your MySQL database. Create a new database and update the database configuration in `app/config/database.py` with your database credentials.

5. Sign up for a free account on `ipdata.co` to obtain an API key. Replace `'YOUR_API_KEY'` in `app/tasks.py` with your actual API key.

## Usage

1. Start the Celery worker:

   ```bash
   celery -A app.config.celery worker --loglevel=info
   ```

2. Start the FastAPI application:

    ```bash
    python3 main.py
    ```

3. Once the application is running, you can interact with it using HTTP requests. Refer to the API documentation for available endpoints and their usage.

## API Documentation

### Authentication Endpoints
- `POST /api/v1/signup`: Register a new user account.
- `POST /api/v1/auth`: Authenticate user credentials and obtain access tokens.
- `POST /api/v1/refresh`: Refresh access tokens using a valid refresh token.

### User Endpoints
- `GET /api/v1/user`: Retrieve user details (requires authentication).


### IP Data Endpoints
- `POST /api/v1/task`: Create a new task to fetch IP data for a given IP address. Returns the task ID.
- `GET /api/v1/status/{task_id}`: Check the status of a task and retrieve the fetched IP data if the task is completed.


## Testing
For running tests, you can use the following command:
```bash
python3 -m unittest discover -s app/tests -p 'test_*.py'
```
