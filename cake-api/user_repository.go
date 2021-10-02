package main

import (
	"errors"
	"sync"
)

type InMemoryUserStorage struct {
	lock    sync.RWMutex
	storage map[string]User
}

func NewInMemoryUserStorage() *InMemoryUserStorage {
	return &InMemoryUserStorage{
		lock:    sync.RWMutex{},
		storage: make(map[string]User),
	}
}

func (userStorage *InMemoryUserStorage) Add(email string, user User) error {
	userStorage.lock.Lock()
	defer userStorage.lock.Unlock()

	_, ok := userStorage.storage[email]

	if ok {
		return errors.New("user already exists")
	} else {
		userStorage.storage[email] = user
	}

	return nil
}

func (userStorage *InMemoryUserStorage) Get(email string) (User, error) {
	userStorage.lock.Lock()
	defer userStorage.lock.Unlock()

	user, ok := userStorage.storage[email]

	if !ok {
		return User{}, errors.New("invalid login credentials")
	}

	return user, nil
}

func (userStorage *InMemoryUserStorage) Update(email string, newUser User) error {
	userStorage.lock.Lock()
	defer userStorage.lock.Unlock()

	_, ok := userStorage.storage[email]

	if !ok {
		return errors.New("invalid login credentials")
	}

	userStorage.storage[email] = newUser

	return nil
}

func (userStorage *InMemoryUserStorage) Delete(email string) (User, error) {
	userStorage.lock.Lock()
	defer userStorage.lock.Unlock()

	user, ok := userStorage.storage[email]

	if !ok {
		return User{}, errors.New("invalid login credentials")
	}

	delete(userStorage.storage, email)

	return user, nil
}
