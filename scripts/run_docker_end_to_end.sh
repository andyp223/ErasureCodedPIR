
docker build -t coded-pir .

# Runs full end-to-end test within Docker container.
docker run -a stdout --env-file .env --name "main" coded-pir sh -c ./scripts/run_end_to_end.sh

# Wait for container to finish.
docker wait main

# Kill docker container if still running and delete container.
docker kill main
docker container rm main





