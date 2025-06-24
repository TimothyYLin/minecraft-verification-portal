# Minecraft Verification Portal
This repository contains a custom Minecraft verification portal that can be used for authentication for users who may be hosting their own Minecraft servers.

This project is the web portal and backend API for the [Minecraft Verification Mod](https://github.com/TimothyYLin/minecraft-verification-mod). It handles user registration, code generation, and verification requests from the in-game mod, linking a player's Minecraft account to their portal account.

For full functionality, this repository **MUST** be used along with the Minecraft mod. At the time of writing, June 21, 2025, this mod only supports Fabric servers.

## Prerequisites
Before you begin, please ensure that the following software is installed on your development machine:

- Node.js (including npm)
- Docker
- A code editor

## Getting Started
The following steps detail the setup process in order to get the portal up and running.

1. **Cloning this repository:**  
```bash
git clone git@github.com:TimothyYLin/minecraft-verification-portal.git <path_to_clone_to>
cd <path_to_clone_to>
```

2. **Installing dependencies:**

- To install all dependencies (including development dependencies):  
    `npm install`
   
- To install production dependencies only:  
    `npm install --production`

3. **Set up the database:**  
   This project requires a PostgreSQL database. For development purposes, the easiest way is to run one locally with Docker.

    a. Setup parameters  
    The following parameters should be setup. They can be setup according to the developer's preference.  
    In this guide, the database data will be stored in a directory within the project structure. The database parameters will be defined in a .env file.   
    
    As a small hint, any long secure passwords/keys can be generated with openssl like so:  
    `openssl rand -base64 32`

    ```bash
    ### postgres.env

    # Username for the database superuser
    POSTGRES_USER=<user>

    # Password for the superuser
    POSTGRES_PASSWORD=<secret_password>

    # Name of default database to be created
    POSTGRES_DB=<database_name>
    ```
    
    b. Start the PostgreSQL Container:  
    The following command will start a Postgres database in the background.
    ```bash
    docker run --name <name> --env-file <env_file> -p <port:port_to_map> -v <volume_or_path:map_into_container> -d postgres
    ```

    An example command could look like:  
    ```bash
    docker run --name minecraft-postgres --env-file ./postgres.env -p 5432:5432 -v ./postgres-data:/var/lib/postgresql/data -d postgres
    ```
4. **Configure Environment Variables:**  
The server requires environment variables to connect to the database and for other security features. There are two separate .env files, one for backend and one for frontend.

    a. Let's start with the backend .env file.  
    Start off by copying the example environment file to create your own local configuration
    ```bash
    cd backend/
    cp example.env .env
    ```  

    b. Edit the .env file with values for your own local setup.
    ```bash
    ### backend/.env

    # The port for the Node.js application to run on  
    PORT=3000

    ## Database information

    # Username for database superuser
    DB_USER=<user>

    # Database host IP
    DB_HOST=<host>

    # Name of database
    DB_DATABASE=<database_name>

    # Database password
    DB_PASSWORD=<password>

    # Port to connect to database
    DB_PORT=<port>

    ## JWT Secrets
    JWT_SECRET=<super_secret_long_key>
    REFRESH_TOKEN_SECRET=<different_super_secret_long_key>

    ## Nodemailer (Gmail) Credentials to send verification emails
    EMAIL_USER=<email_address>
    EMAIL_PASS=<email_password_or_google_application_password>

    # Application public base URL
    APP_BASE_URL=<url>

    # Frontend URL for redirecting
    FRONTEND_URL=<frontend_url>

    # Internal API key for internal routes
    INTERNAL_API_KEY=<long_super_secret_key>
    ```

    An example .env file may look like this:
    ```bash
    ### backend/.env

    PORT=3000

    DB_USER=postgres
    DB_HOST=localhost
    DB_DATABASE=postgres
    DB_PASSWORD=<long_secure_password>
    DB_PORT=5432

    JWT_SECRET=<long_secure_jwt_secret>
    REFRESH_TOKEN_SECRET=<long_secure_refresh_token>

    EMAIL_USER="SampleEmail@gmail.com"
    EMAIL_PASS=<long_secure_email_application_password>

    APP_BASE_URL="http://localhost:3000"
    FRONTEND_URL+"https://localhost:5173"

    INTERNAL_API_KEY=<long_secure_internal_api_key>
    ```

    c. Next, let's move into the simpler frontend .env file.
    ```bash
    cd frontend/
    cp example.env .env
    ```

    d. The frontend .env is simple and straightforward with just variables used in build tools like Vite. A sample .env may look like the following and not require any changing unless your API path changes.
    ```bash
    ### frontend.env
    VITE_API_BASE_URL="/api"
    ```

5. **Running the Application**  
The application has two primary run modes.  

- For Development  
The following command will start the server using a tool like `nodemon`, which automatically restarts the application whenever you save a file:  
`npm run dev`

- For Production  
The following command will start the server in a standard production mode:  
`npm start`

Once running, the API should be availble based on the previously configured .env files. In the examples given above, this would be `http://localhost:3000`
    

