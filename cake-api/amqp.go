package main

import (
	"log"

	"github.com/streadway/amqp"
)

const (
	amqpPath = "amqp://guest:guest@localhost:5672/"
)

func runPublisher(send chan []byte) {
	conn, err := amqp.Dial(amqpPath)
	if err != nil {
		log.Fatalf("Failed to connect to RabbitMQ: %s", err)
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Failed to open a channel: %s", err)
	}
	defer ch.Close()

	q, err := ch.QueueDeclare(
		"default",
		false,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to declare a queue: %s", err)
	}

	for body := range send {
		err = ch.Publish(
			"",
			q.Name,
			false,
			false,
			amqp.Publishing{
				ContentType: "text/plain",
				Body:        body,
			},
		)
	}
}
