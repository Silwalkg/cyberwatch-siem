# System Architecture

## Overview

CyberWatch SIEM follows a client-server architecture:

`mermaid
graph TD
    A[Browser] -->|HTTP/WS| B[FastAPI Backend]
    B -->|SQLAlchemy ORM| C[SQLite Database]
    B -->|WebSocket| A
    A -->|REST API| B
``n
## Components

- **Frontend**: HTML/CSS/JS with Chart.js
- **Backend**: FastAPI (Python)
- **Database**: SQLite via SQLAlchemy
- **Auth**: JWT tokens via python-jose
- **Real-time**: WebSocket for live event streaming
