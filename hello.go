package main

import (
	//"encoding/base64"
	"crypto/aes"
	dilithium "crystals-dilithium"
	"encoding/hex"
	"fmt"
	"log"

	//"unsafe"
	//"reflect"
	//dilithium "github.com/kudelskisecurity/crystals-go/crystals-dilithium"

	//"mux-main"
	"net/http"

	"github.com/gin-gonic/gin"
)

/*
	type todo struct {
		ID        string `json:"id"`
		Item      string `json:"item"`
		Completed bool   `json:"completed"`
	}

	var todos = []todo{
		{ID: "1", Item: "clean", Completed: false},
		{ID: "2", Item: "read", Completed: false},
		{ID: "3", Item: "record", Completed: false},
	}

	func getTodos(context *gin.Context) {
		fmt.Println("gettodo")
		context.IndentedJSON(http.StatusOK, todos)
	}

	func addTodo(context *gin.Context) {
		fmt.Println("addtodo")
		var newTodo todo

		if err := context.BindJSON(&newTodo); err != nil {
			return
		}

		todos = append(todos, newTodo)

		context.IndentedJSON(http.StatusCreated, newTodo)
	}
*/
// See NIST's PQCgenKAT.c.
type DRBG struct {
	key [32]byte
	v   [16]byte
}

func (g *DRBG) incV() {
	for j := 15; j >= 0; j-- {
		if g.v[j] == 255 {
			g.v[j] = 0
		} else {
			g.v[j]++
			break
		}
	}
}

// AES256_CTR_DRBG_Update(pd, &g.key, &g.v)
func (g *DRBG) update(pd *[48]byte) {
	var buf [48]byte
	b, _ := aes.NewCipher(g.key[:])
	for i := 0; i < 3; i++ {
		g.incV()
		b.Encrypt(buf[i*16:(i+1)*16], g.v[:])
	}
	if pd != nil {
		for i := 0; i < 48; i++ {
			buf[i] ^= pd[i]
		}
	}
	copy(g.key[:], buf[:32])
	copy(g.v[:], buf[32:])
}

// randombyte_init(seed, NULL, 256)
func NewDRBG(seed *[48]byte) (g DRBG) {
	g.update(seed)
	return
}

func (g *DRBG) Fill(x []byte) {
	var block [16]byte

	b, _ := aes.NewCipher(g.key[:])
	for len(x) > 0 {
		g.incV()
		b.Encrypt(block[:], g.v[:])
		if len(x) < 16 {
			copy(x[:], block[:len(x)])
			break
		}
		copy(x[:], block[:])
		x = x[16:]
	}
	g.update(nil)
}

var d *dilithium.Dilithium
var pk []byte
var sk []byte

type sign struct {
	Msg       string `json:"message"`
	Signature string `json:"signature"`
	Sk        string `json:"private key"`
}

var signs = []sign{}

func do_sign(context *gin.Context) {
	fmt.Println("do_sign")
	var newSign sign

	if err := context.BindJSON(&newSign); err != nil {
		return
	}

	signs = append(signs, newSign)

	m := newSign.Msg
	sign_msg, err := hex.DecodeString(m)
	if err != nil {
		log.Fatal(err)
	}
	s := newSign.Sk
	sign_sk, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	sig := d.Sign(sign_sk, sign_msg)
	newSign.Signature = hex.EncodeToString(sig)
	newSign.Sk = ""
	context.IndentedJSON(http.StatusCreated, newSign)
}

type gen struct {
	D_level string `json:"level"`
	Pk      string `json:"public key"`
	Sk      string `json:"private key"`
	Seed    string `json:"seed"`
}

var gens = []gen{}

func do_gen(context *gin.Context) {
	fmt.Println("do_gen")
	var newGen gen

	if err := context.BindJSON(&newGen); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	gens = append(gens, newGen)

	level := newGen.D_level
	fmt.Println("level: ", level)

	if level == "2" {
		d = dilithium.NewDilithium2(false)
	} else if level == "3" {
		d = dilithium.NewDilithium3(false)
	} else if level == "5" {
		d = dilithium.NewDilithium5(false)
	} else {
		fmt.Println("沒有相符的level")
	}
	fmt.Println("len of seed", len(newGen.Seed))

	if len(newGen.Seed) != 96 {
		pk, sk = d.KeyGen(nil)
	} else {
		//randombytes_init(entropy_input, NULL, 256);
		hexStr := newGen.Seed
		var seed [48]byte
		for i := 0; i < 48; i++ {
			seed[i] = byte(i) //entropy_input
		}
		for i := 0; i < 48; i++ {
			byteVal, err := hex.DecodeString(hexStr[i*2 : i*2+2])
			if err != nil {
				log.Fatal(err)
			}
			seed[i] = byteVal[0]

		}
		g2 := NewDRBG(&seed)
		var extSeed [32]byte
		g2.Fill(extSeed[:])
		pk, sk = d.KeyGen(extSeed[:])
	}
	newGen.Pk = hex.EncodeToString(pk)
	newGen.Sk = hex.EncodeToString(sk)
	context.IndentedJSON(http.StatusCreated, newGen)
}

type verify struct {
	Pk        string `json:"public key"`
	Signature string `json:"signature"`
	Outcome   string `json:"outcome"`
	Msg       string `json:"message"`
}

func do_verify(context *gin.Context) {
	fmt.Println("do_verify")
	var newVerify verify

	if err := context.BindJSON(&newVerify); err != nil {
		return
	}

	m := newVerify.Msg
	verify_msg, err := hex.DecodeString(m)
	if err != nil {
		log.Fatal(err)
	}

	sig := newVerify.Signature
	verify_signature, err := hex.DecodeString(sig)
	if err != nil {
		log.Fatal(err)
	}

	p := newVerify.Pk
	verify_pk, err := hex.DecodeString(p)
	if err != nil {
		log.Fatal(err)
	}

	verified := d.Verify(verify_pk, verify_msg, verify_signature)
	if verified {
		println("verify valid")
		newVerify.Outcome = "verify valid"
	}
	if !verified {
		println("verify invalid")
		newVerify.Outcome = "verify invalid"
	}
	newVerify.Pk = ""
	newVerify.Signature = ""
	context.IndentedJSON(http.StatusCreated, newVerify)
}

func main() {

	router := gin.Default()
	router.POST("/sign", do_sign)
	router.POST("/gen", do_gen)
	router.POST("/verify", do_verify)
	router.Run("localhost:9090")

}
