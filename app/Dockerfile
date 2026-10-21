FROM eclipse-temurin:17-jdk AS build
WORKDIR /src
COPY . .
RUN ./mvnw -B -q -DskipTests package

FROM eclipse-temurin:17-jre
RUN useradd --system --uid 10001 app
USER 10001
COPY --from=build /src/target/notes-api-*.jar /app/app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
