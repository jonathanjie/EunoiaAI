# **MarinaGPT**

MarinaGPT is a Django application that provides a variety of features including user management, agent management, organization management, and various APIs. The application uses a PostgreSQL database for data storage and Upstash for caching.

## **Prerequisites**

- Python 3.6 or higher
- pip (Python package installer)
- Virtualenv (Optional but recommended)
- PostgreSQL
- Upstash account

## **Step-by-step Deployment Guide**

1. **Clone the repository**: Use **`git clone`** to clone the MarinaGPT repository to your local machine.
2. **Create a virtual environment (optional but recommended)**: This helps to keep the dependencies required by different projects separate by creating isolated Python environments for them.
    - Install virtualenv: **`pip install virtualenv`**
    - Navigate to the project directory: **`cd MarinaGPT`**
    - Create a new virtual environment: **`virtualenv venv`**
    - Activate the environment:
        - On Windows, run: **`venv\Scripts\activate`**
        - On Unix or MacOS, run: **`source venv/bin/activate`**
3. **Install Django and other dependencies**: The application should have a **`requirements.txt`** file listing all the required Python packages. Install them using pip: **`pip install -r requirements.txt`**
4. **Setup PostgreSQL database**:
    - Install PostgreSQL and make sure the service is running.
    - Create a new PostgreSQL database for the application.
    - Create a new PostgreSQL user and grant this user necessary permissions on the database.
5. **Configure the application settings**:
    - Open the **`settings.py`** file in the MarinaGPT application directory.
    - Set the **`DATABASES`** configuration to point to your PostgreSQL database.
    - Set the **`UPSTASH_REDIS_URL`** to your Upstash Redis URL.
    - Provide necessary keys for Pinecone and OpenAI's Embeddings API.
6. **Initialize the database**: Django comes with a built-in command to automatically create tables in your database according to the database models. Run the following command to initialize the database: **`python manage.py migrate`**
7. **Collect static files**: Run **`python manage.py collectstatic`** to collect all the static files into the directory specified by **`STATIC_ROOT`** in your settings file.
8. **Run the server**: You can now run the server using the following command: **`python manage.py runserver`**. This will start the server on **`localhost:8000`** by default.
9. **Visit the application**: Open your web browser and visit **`http://localhost:8000`** (or whatever your server address is).