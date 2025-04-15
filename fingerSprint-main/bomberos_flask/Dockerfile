# Stage 1: Build the application
FROM eclipse-temurin:17-jdk AS builder

RUN apt-get update && apt-get install -y maven

WORKDIR /app

COPY . .

# Ir al subdirectorio real del proyecto
WORKDIR /app/fingerSprint-main

RUN mvn clean package -DskipTests

# Stage 2: Run the application
FROM eclipse-temurin:17-jre

WORKDIR /app

COPY --from=builder /app/fingerSprint-main/target/bomberos_flask-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
