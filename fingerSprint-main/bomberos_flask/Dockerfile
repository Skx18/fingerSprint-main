# Stage 1: Build the application
FROM eclipse-temurin:17-jdk AS builder

# Instala Maven
RUN apt-get update && apt-get install -y maven

# Establece el directorio de trabajo
WORKDIR /app

# Copia todo el contenido del contexto (incluyendo fingerSprint-main/)
COPY . .

# Cambia al subdirectorio del proyecto donde está el pom.xml
WORKDIR /app/fingerSprint-main/bomberos_flask

# Compila sin tests
RUN mvn clean package -DskipTests

# Stage 2: Run the application
FROM eclipse-temurin:17-jre

WORKDIR /app

# Copia el .jar desde la etapa anterior (ajustando la ruta)
COPY --from=builder /app/fingerSprint-main/bomberos_flask/target/bomberos_flask-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
