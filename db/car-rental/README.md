# car-rental

> Car rental website providing the services of a given rental company, including car rental, car return, rental
> extension and monitoring orders.

## Table of Contents

* [General Info](#general-information)
* [Technologies Used](#technologies-used)
* [Features](#features)
* [Screenshots](#screenshots)
* [Usage](#usage)
* [Room for Improvement](#room-for-improvement)

## General Information

The goal of this project was to learn how to write REST API's using Spring and gain general knowledge about Angular. An
additional challenge was to secure it with JSON Web Token.

## Technologies Used

- Angular - version 15.1.6.
- Spring Boot - version 3.0.2
- Bootstrap - version 5.3.0
- MySQL with Spring Data JPA - version 8.0
- Docker - version 23.0.3

## Features

- User registration and login (secured by JWT)
- Renting a car, extending rental and returning cars
- Current rentals page
- Filtering and sorting offers
- Input validation

## Screenshots

[Deleted]

## Usage

```bash
docker-compose up --detach
```


## Room for Improvement

Room for improvement:

- Even more validation of the input should be done

To do:

- Unit tests for both backend and frontend
- Order history
- Discount for loyal customers
