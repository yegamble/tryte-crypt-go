package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"strconv"
)

var defaultOptions tryteCipher.ScryptOptions

func SetRoutes() {
	app := fiber.New()

	seedHandler := app.Group("/", logger.New())

	seedHandler.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON("Welcome to Seed Generator")
	})

	seedHandler.Post("/encrypt", func(c *fiber.Ctx) error {
		return encryptSeed(c)
	})

	seedHandler.Post("/decrypt", func(c *fiber.Ctx) error {
		return decryptSeed(c)
	})

	seedHandler.Post("/generate", func(c *fiber.Ctx) error {
		return generateAndEncryptSeed(c)
	})

	err := app.Listen("localhost:3000")
	if err != nil {
		panic(err)
	}
}

func encryptSeed(c *fiber.Ctx) error {

	seed := c.FormValue("seed")
	if seed == "" {
		return c.Status(fiber.StatusOK).JSON("Seed is Required")
	} else if trinary.ValidTrytes(seed) != nil {
		return c.Status(fiber.StatusOK).JSON("Seed is Not a Valid 81-tryte Input")
	}

	passphrase := c.FormValue("passphrase")
	if passphrase == "" {
		return c.Status(fiber.StatusOK).JSON("Passphrase is Required")
	}

	toughness, err := strconv.Atoi(c.FormValue("difficulty"))
	if err != nil {
		return c.Status(fiber.StatusOK).JSON("Encryption Difficulty is Not a Valid Number")
	} else if toughness > 20 {
		return c.Status(fiber.StatusOK).JSON("Encryption Difficulty Cannot Exceed 20")
	}

	encrypt, err := tryteCipher.Encrypt(seed, passphrase, defaultOptions, toughness)
	if err != nil {
		return c.Status(fiber.StatusOK).JSON(err.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"encrypted_seed": encrypt,
	})
}

func decryptSeed(c *fiber.Ctx) error {

	seed := c.FormValue("seed")
	if seed == "" {
		return c.Status(fiber.StatusOK).JSON("Seed is Required")
	}

	passphrase := c.FormValue("passphrase")
	if passphrase == "" {
		return c.Status(fiber.StatusOK).JSON("Passphrase is Required")
	}

	decrypt, err := tryteCipher.Decrypt(seed, passphrase, defaultOptions)
	if err != nil {
		return c.Status(fiber.StatusOK).JSON(err.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"seed": decrypt,
	})
}

func generateAndEncryptSeed(c *fiber.Ctx) error {

	passphrase := c.FormValue("passphrase")
	if passphrase == "" {
		return c.Status(fiber.StatusOK).JSON("Passphrase is Required")
	}

	seed, err := tryteCipher.GenerateRandomSeed()
	if err != nil {
		return c.Status(fiber.StatusOK).JSON(err.Error())
	}

	toughness, err := strconv.Atoi(c.FormValue("difficulty"))
	if err != nil {
		return c.Status(fiber.StatusOK).JSON("Encryption Difficulty is Not a Valid Number")
	} else if toughness > 20 {
		return c.Status(fiber.StatusOK).JSON("Encryption Difficulty Cannot Exceed 20")
	}

	encrypt, err := tryteCipher.Encrypt(seed, passphrase, defaultOptions, toughness)
	if err != nil {
		return c.Status(fiber.StatusOK).JSON(seed)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"seed":           seed,
		"encrypted_seed": encrypt,
	})
}
