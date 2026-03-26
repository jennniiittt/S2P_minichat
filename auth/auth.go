package auth

import (
    "encoding/json"
    "errors"
    "golang.org/x/crypto/bcrypt"
    "io/ioutil"
    "os"
)

type User struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

// Load all users
func LoadUsers(path string) ([]User, error) {
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return []User{}, nil // return empty if file not exists
    }
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var users []User
    err = json.Unmarshal(data, &users)
    return users, err
}

// Save users
func SaveUsers(path string, users []User) error {
    data, err := json.MarshalIndent(users, "", "  ")
    if err != nil {
        return err
    }
    return ioutil.WriteFile(path, data, 0644)
}

// Sign up
func Signup(path, username, password string) error {
    users, err := LoadUsers(path)
    if err != nil {
        return err
    }
    // check duplicate username
    for _, u := range users {
        if u.Username == username {
            return errors.New("username already exists")
        }
    }
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return err
    }
    users = append(users, User{Username: username, Password: string(hash)})
    return SaveUsers(path, users)
}

// Authenticate login
func Authenticate(path, username, password string) error {
    users, err := LoadUsers(path)
    if err != nil {
        return err
    }
    for _, u := range users {
        if u.Username == username {
            return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
        }
    }
    return errors.New("user not found")
}