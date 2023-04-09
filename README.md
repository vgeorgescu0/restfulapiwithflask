# Building a RESTful API with Flask

CPSC 449 - Backend

This is an API using MySQL as databse to demonstrate flask initialization and connection to database, use of error handling, authentication using JWT, file handling for uploading, and public routes.

Contributing Members: Gabriel Warkentin, Victor Georgescu

All testing and execution performed on Python 3.10.9, not tested for other versions at this time. Please use this package for proper execution.

# Pre-Reqs

This API uses MySQL as database. See schemas below for assistance with creating database for full functioning.

```
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `password` varchar(256) NOT NULL,
  `email` varchar(320) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`)
```

```
CREATE TABLE `movies` (
  `movie` varchar(255) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `rating` decimal(3,1) DEFAULT NULL,
  UNIQUE KEY `movie_UNIQUE` (`movie`)
```

# Instructions

To build the flask app first begin with creating a virtual environment using the below command

>`python3 -m venv venv`
>
>`source venv/bin/activate`
>
>`pip install -r requirements.txt`

After build is complete, run the app with below command

>`python3 app.py`

# Contributions

All work has been completed by listed collaborators above.
