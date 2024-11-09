# CyberSecurityDashboard

## Overview

The **CyberSecurityDashboard** is a comprehensive tool designed to simulate a healthcare application vulnerable to various cyber-attacks, including DDoS, XSS, and SQL injection. It integrates Kitsune, an anomaly detection system, to monitor and detect these attacks in real-time. The project utilizes Docker for containerization, ensuring a consistent and isolated environment for deployment and testing.

## Features

- **Vulnerable Healthcare Application**: A simulated healthcare platform intentionally designed with vulnerabilities to facilitate security testing and research.
- **Anomaly Detection with Kitsune**: Integration of Kitsune to monitor network traffic and detect anomalies indicative of cyber-attacks.
- **Dashboard Interface**: A user-friendly dashboard to visualize detected anomalies and monitor the application's security status.
- **Dockerized Setup**: Utilization of Docker to containerize the application, ensuring ease of deployment and consistency across different environments.

## Prerequisites

Before setting up the project, ensure that the following software is installed on your system:

- **Docker**: A platform for developing, shipping, and running applications in containers.
- **Docker Compose**: A tool for defining and running multi-container Docker applications.

### Installing Docker and Docker Compose

1. **Docker**:
   - **Windows and macOS**:
     - Download and install Docker Desktop from the [official Docker website](https://www.docker.com/products/docker-desktop).
   - **Linux**:
     - Follow the [official Docker installation guide](https://docs.docker.com/engine/install/) for your specific Linux distribution.

2. **Docker Compose**:
   - Docker Compose is included with Docker Desktop for Windows and macOS.
   - For Linux:
     - Follow the [official Docker Compose installation instructions](https://docs.docker.com/compose/install/) to install it on your system.

## Setup Instructions

Follow these steps to set up and run the CyberSecurityDashboard:

1. **Clone the Repository**:
   - Open your terminal or command prompt.
   - Navigate to the directory where you want to clone the repository.
   - Run the following command:

     ```bash
     git clone https://github.com/saikumaresh/CyberSecurityDashboard.git
     ```

   - Alternatively, download the ZIP file from the repository's GitHub page and extract it to your desired location.

2. **Navigate to the Project Directory**:
   - Change your directory to the project's root directory:

     ```bash
     cd CyberSecurityDashboard
     ```

3. **Build and Start the Docker Containers**:
   - Ensure Docker is running on your system.
   - In the project's root directory, execute the following command:

     ```bash
     docker-compose up --build
     ```

   - This command will build the Docker images and start the containers as defined in the `docker-compose.yml` file.

4. **Access the Application and Dashboard**:
   - Once the containers are up and running:
     - **Healthcare Application**: Access it by navigating to `http://localhost:5000` in your web browser.
     - **Dashboard**: Access it by navigating to `http://localhost:3000` in your web browser.

## Simulating Attacks

The CyberSecurityDashboard allows you to simulate various cyber-attacks to test the application's security and observe how the integrated anomaly detection system responds.

### 1. SQL Injection Attack

- **Description**: SQL Injection involves inserting malicious SQL queries into input fields to manipulate the database.
- **Simulation Steps**:
  - Navigate to the login page of the healthcare application.
  - In the username or password field, enter the following payload:

    ```
    ' OR 1=1 --
    ```

  - Attempt to log in and observe the application's response.

### 2. Cross-Site Scripting (XSS) Attack

- **Description**: XSS attacks involve injecting malicious scripts into web pages viewed by other users.
- **Simulation Steps**:
  - Find a form or input field in the application that displays user input.
  - Enter the following script into the input field:

    ```html
    <script>alert('XSS');</script>
    ```

  - Submit the form and observe if an alert box appears, indicating a successful XSS attack.

### 3. Distributed Denial of Service (DDoS) Attack

- **Description**: DDoS attacks aim to overwhelm the application's resources, making it unavailable to legitimate users.
- **Simulation Steps**:
  - **Install hping3**:
    - On a Linux system, install hping3 using the following command:

      ```bash
      sudo apt-get install hping3
      ```

  - **Execute the Attack**:
    - Run the following command to simulate a DDoS attack:

      ```bash
      sudo hping3 -i u40 -S -p 80 -c 100000 [URL of the Healthcare website]
      ```

    - Replace `[URL of the Healthcare website]` with the actual URL or IP address of the healthcare application (e.g., `localhost` or `127.0.0.1`).

    - **Note**: This command sends a large number of SYN packets to the specified URL, simulating a DDoS attack. Use this responsibly and only in a controlled environment.

## Monitoring and Detection

- After simulating the attacks, navigate to the dashboard (`http://localhost:3000`) to monitor the application's security status.
- The dashboard will display detected anomalies and provide insights into potential vulnerabilities.

## Project Structure

The project is organized as follows:

- **`vulnerable-site/`**: Contains the source code for the vulnerable healthcare application.
- **`status_checker/`**: Includes scripts and configurations for monitoring the application's status and integrating Kitsune.
- **`dashboard/`**: Houses the code for the dashboard interface to visualize detected anomalies.
- **`docker-compose.yml`**:
::contentReference[oaicite:0]{index=0}
 
