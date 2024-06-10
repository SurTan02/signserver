FROM eclipse-temurin:17-jdk-alpine

# Define environment variables
ENV JAR_FILE=target/signserver-v1.jar
ENV APP_PROPS_FILE=target/classes/application.properties
ENV JSON_FILE=target/classes/tugas-akhir-420415-2db8c1ea368b.json

# Set the working directory
WORKDIR /usr/src/app

# Copy the JAR file and other necessary files
COPY $JAR_FILE app.jar
COPY $APP_PROPS_FILE application.properties
COPY $JSON_FILE tugas-akhir-420415-2db8c1ea368b.json

# Define the entry point with the environment variables
ENTRYPOINT ["java", "-jar", "/usr/src/app/app.jar", "--spring.config.location=/usr/src/app/application.properties"]
