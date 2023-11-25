# Twitter Clone - Laravel Backend

## Introduction

This repository contains the backend codebase for the Twitter Clone project. It's developed using Laravel, providing API functionalities to the Twitter Clone frontend.

## Getting Started

### Installation

1. Clone the project repository:

   ```bash
   git clone https://github.com/anisAronno/twitter-backend.git
   ```

2. Move into the project directory:

   ```bash
   cd twitter-backend
   ```

3. Install PHP dependencies using Composer:

   ```bash
   composer install
   ```

4. Copy the environment variables file:

   ```bash
   cp .env.example .env
   ```

5. Set up your environment variables, including the `FRONTEND_URL`:

   ```
   FRONTEND_URL=http://localhost:3139
   ```

6. Generate your application key:

   ```bash
   php artisan key:generate
   ```

7. Create symbolic links for storage:

   ```bash
   php artisan storage:link
   ```

### Database Setup

1. Run database migrations:

   ```bash
   php artisan migrate
   ```

2. Seed the database with sample data (if available):

   ```bash
   php artisan db:seed
   ```

### Running the Application

1. Start your local development server:

   ```bash
   php artisan serve
   ```

2. To process mail jobs, execute:

   ```bash
   php artisan queue:work
   ```

### Additional Commands

- For frontend development build:

  ```bash
  npm run dev
  ```

- For production frontend build:

  ```bash
  npm run build
  ```

### Caching with Redis

Ensure Redis is installed and configured in your environment for caching functionalities.

## API Documentation

The API documentation is available in the 'DOCS' folder within this backend project. Refer to it for detailed API endpoints and usage.

## Frontend Repository

For the frontend of the Twitter Clone project, visit the repository at [Twitter Frontend](https://github.com/anisAronno/twitter-frontend).
 
## License

This project is open-source software licensed under the [MIT license](https://opensource.org/licenses/MIT).