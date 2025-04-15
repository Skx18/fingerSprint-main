# Stage 1: Build the application
FROM eclipse-temurin:17-jdk AS builder

# Set the working directory
WORKDIR /app

# Copy the entire project
COPY . .

# Damos permisos a mvnw si está en el proyecto
RUN chmod +x mvnw || true

# Compilamos la app
RUN ./mvnw clean package -DskipTests || mvn clean package -DskipTests

# Stage 2: Run the application
FROM eclipse-temurin:17-jre

WORKDIR /app

# Copiamos el .jar desde el stage anterior
COPY --from=builder /app/target/bomberos_flask-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
