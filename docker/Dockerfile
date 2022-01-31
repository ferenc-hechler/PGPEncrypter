FROM openjdk:8-alpine

WORKDIR /app
COPY app /app


VOLUME /INPUT
VOLUME /OUTPUT
VOLUME /APPDATA

#RUN adduser -u 33 -G root -D www-data
USER www-data:root

# change "/app/encrypt-key.pub" to "/APPDATA/encrypt-key.pub" to use a key provided from outside
CMD java -Xmx128m -jar pgpencrypter.jar /app/encrypt-key.pub /INPUT /OUTPUT /APPDATA/synced-files.csv
