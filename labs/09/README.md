# Lab 09 - Developing Secure Web Applications and REST APIs

## Prerequisites

- Docker & Docker Compose
- Java 17+
- Maven (or use the Maven wrapper in the project)
- IntelliJ IDEA (recommended) or another IDE

---

## Step 1: Start the Database

```bash
cd /Users/jankott/ZHAW/software-and-system-security-1/labs/09

# Start MySQL container
docker compose up -d

# Verify it's running
docker compose ps

# Wait ~10 seconds for MySQL to initialize, then check logs
docker compose logs mysql
```

You should see "ready for connections" in the logs.

**To reset the database later:**
```bash
docker compose down -v
docker compose up -d
```

---

## Step 2: Run the Web Application

### Option A: Using IntelliJ

1. Open `Marketplace_Lab` folder in IntelliJ
2. Wait for Maven to import dependencies
3. In the top-right, select **"Marketplace Web"** from the run configuration dropdown
4. Click the green **Run** button
5. Wait for "Started MarketplaceApplication" in the console

### Option B: Using Command Line

```bash
cd /Users/jankott/ZHAW/software-and-system-security-1/labs/09/Marketplace_Lab

# Build the project
./mvnw clean install -DskipTests

# Run the web application
./mvnw spring-boot:run -pl Marketplace-web
```

---

## Step 3: Access the Web Application

Open your browser and go to:

```
https://localhost:8443
```

**Accept the certificate warning** (it's a self-signed certificate for development).

---

## Step 4: Test Users

| Username | Password   | Role            |
|----------|------------|-----------------|
| alice    | rabbit     | SALES           |
| bob      | patrick    | BURGERMAN       |
| daisy    | yellow     | PRODUCTMANAGER  |
| john     | wildwest   | SALES           |
| luke     | force      | PRODUCTMANAGER  |
| robin    | arrow      | MARKETING       |
| snoopy   | woodstock  | MARKETING       |

---

## Step 5: Run the REST API (for Task 4)

**Stop the Web Application first!** (Both use port 8443)

### Option A: Using IntelliJ

1. Select **"Marketplace REST"** from the run configuration dropdown
2. Click the green **Run** button

### Option B: Using Command Line

```bash
cd /Users/jankott/ZHAW/software-and-system-security-1/labs/09/Marketplace_Lab

./mvnw spring-boot:run -pl Marketplace-rest
```

---

## Step 6: Run REST API Tests (for Task 4)

1. Make sure the **REST API is running** (not the web app)
2. Reset the database first:
   ```bash
   docker compose down -v && docker compose up -d
   ```
3. Wait 10 seconds for MySQL to initialize

### Option A: Using IntelliJ

1. Open `Marketplace_Lab_REST-Test` in a **new IntelliJ window**
2. Run the `Test` class (click Run in the toolbar)

### Option B: Using Command Line

```bash
cd /Users/jankott/ZHAW/software-and-system-security-1/labs/09/Marketplace_Lab_REST-Test

./mvnw exec:java -Dexec.mainClass="Test"
```

---

## After Task 3: Encrypt Credit Cards

After implementing credit card encryption, update existing records:

```bash
docker exec -i marketplace-mysql mysql -uroot -proot < Marketplace_UpdateEncryptedCreditCards.sql
```

---

## Useful Commands

```bash
# Check if MySQL is running
docker compose ps

# View MySQL logs
docker compose logs -f mysql

# Connect to MySQL directly
docker exec -it marketplace-mysql mysql -uroot -proot marketplace

# Stop everything
docker compose down

# Reset database completely
docker compose down -v && docker compose up -d
```

---

## Troubleshooting

### "Connection refused" error
- Make sure Docker is running: `docker compose ps`
- Wait 10-15 seconds after starting the container

### Port 8443 already in use
- Stop the other application (Web or REST) before starting the new one
- Or kill the process: `lsof -i :8443` then `kill <PID>`

### Database not initializing
```bash
docker compose down -v
docker compose up -d
```

### Certificate warning in browser
- Click "Advanced" → "Proceed to localhost (unsafe)"
- This is normal for self-signed certificates

---

## Attack Page (for testing)

Access the attack page for security testing:
```
https://localhost:8443/public/attacks
```

This page has buttons to test various attack scenarios mentioned in the lab.
