package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"
)

var db *sql.DB

var progress float64 = 0
var totalPackets int = 0

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Erro ao carregar arquivo .env:", err)
	}

	verifyDatabase()

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Erro ao conectar ao banco de dados:", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatal("Erro ao pingar o banco de dados:", err)
	}

	createTable()

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")
	r.GET("/", showHomePage)
	r.POST("/upload", uploadPCAP)
	r.GET("/timeline", timelinePage)

	r.GET("/api/timeline", getTimelineData)
	r.GET("/api/ips", getDistinctIPs)
	r.GET("/api/progress", getProgress)
	r.GET("/api/protocols", getProtocols)
	r.GET("/api/events", getEvents)


	fmt.Println("Servidor iniciado em http://localhost:8080")
	r.Run(":8080")
}

func verifyDatabase() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
	)
	tmpDb, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Erro ao conectar ao MySQL:", err)
	}
	defer tmpDb.Close()

	dbName := os.Getenv("DB_NAME")
	_, err = tmpDb.Exec("CREATE DATABASE IF NOT EXISTS " + dbName)
	if err != nil {
		log.Fatal("Erro ao criar o banco de dados:", err)
	}
}

func createTable() {
	query := `CREATE TABLE IF NOT EXISTS events (
		id INT AUTO_INCREMENT PRIMARY KEY,
		ip VARCHAR(255),
		protocol VARCHAR(255),
		timestamp VARCHAR(255)
	);`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}
}

func showHomePage(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

func timelinePage(c *gin.Context) {
	c.HTML(http.StatusOK, "timeline.html", nil)
}

func uploadPCAP(c *gin.Context) {
	file, err := c.FormFile("pcap")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Falha ao fazer upload do arquivo"})
		return
	}
	filePath := "uploads/" + file.Filename
	err = c.SaveUploadedFile(file, filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao salvar arquivo"})
		return
	}

	go parsePCAP(filePath)

	c.Redirect(http.StatusSeeOther, "/timeline")
}

func countPackets(filePath string) (int, error) {
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		return 0, err
	}
	defer handle.Close()
	count := 0
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for range packetSource.Packets() {
		count++
	}
	return count, nil
}

func parsePCAP(filePath string) {
	total, err := countPackets(filePath)
	if err != nil {
		log.Println("Erro ao contar pacotes:", err)
		return
	}
	totalPackets = total
	progress = 0
	processed := 0

	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		log.Println("Erro ao abrir arquivo PCAP:", err)
		return
	}
	defer handle.Close()

	tx, err := db.Begin()
	if err != nil {
		log.Println("Erro ao iniciar transação:", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO events (ip, protocol, timestamp) VALUES (?, ?, ?)")
	if err != nil {
		log.Println("Erro ao preparar statement:", err)
		return
	}
	defer stmt.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			processed++
			progress = (float64(processed) / float64(totalPackets)) * 100
			continue
		}
		ip := netLayer.NetworkFlow().Src().String()
		var protocol string
		if packet.TransportLayer() != nil {
			protocol = packet.TransportLayer().LayerType().String()
		} else {
			protocol = "Desconhecido"
		}
		timestamp := packet.Metadata().Timestamp.Format(time.RFC3339)

		_, err := stmt.Exec(ip, protocol, timestamp)
		if err != nil {
			log.Println("Erro ao inserir no banco:", err)
		}
		processed++
		progress = (float64(processed) / float64(totalPackets)) * 100
	}
	err = tx.Commit()
	if err != nil {
		log.Println("Erro ao commitar transação:", err)
	}
	log.Printf("Processamento concluído: %d pacotes processados", processed)
	progress = 100
}

func getTimelineData(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parâmetro 'ip' é obrigatório"})
		return
	}
	protocol := c.Query("protocol")
	view := c.DefaultQuery("view", "summarized")

	var rows *sql.Rows
	var err error

	if view == "summarized" {
		if protocol != "" {
			query := "SELECT DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i') as minute, COUNT(*) as count FROM events WHERE ip = ? AND protocol = ? GROUP BY minute ORDER BY minute ASC"
			rows, err = db.Query(query, ip, protocol)
		} else {
			query := "SELECT DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i') as minute, COUNT(*) as count FROM events WHERE ip = ? GROUP BY minute ORDER BY minute ASC"
			rows, err = db.Query(query, ip)
		}
	} else if view == "complete" {
		if protocol != "" {
			query := "SELECT timestamp FROM events WHERE ip = ? AND protocol = ? ORDER BY timestamp ASC"
			rows, err = db.Query(query, ip, protocol)
		} else {
			query := "SELECT timestamp FROM events WHERE ip = ? ORDER BY timestamp ASC"
			rows, err = db.Query(query, ip)
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "View inválida"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro na consulta"})
		return
	}
	defer rows.Close()

	var timeline []map[string]interface{}
	if view == "summarized" {
		for rows.Next() {
			var minute string
			var count int
			rows.Scan(&minute, &count)
			timeline = append(timeline, map[string]interface{}{"minute": minute, "count": count})
		}
	} else {
		for rows.Next() {
			var ts time.Time
			rows.Scan(&ts)
			timeline = append(timeline, map[string]interface{}{"timestamp": ts.Format(time.RFC3339), "count": 1})
		}
	}
	c.JSON(http.StatusOK, timeline)
}

func getProtocols(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parâmetro 'ip' é obrigatório"})
		return
	}
	rows, err := db.Query("SELECT DISTINCT protocol FROM events WHERE ip = ?", ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro na consulta"})
		return
	}
	defer rows.Close()
	var protocols []string
	for rows.Next() {
		var protocol string
		rows.Scan(&protocol)
		protocols = append(protocols, protocol)
	}
	c.JSON(http.StatusOK, protocols)
}

func getDistinctIPs(c *gin.Context) {
	rows, err := db.Query("SELECT DISTINCT ip FROM events")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro na consulta"})
		return
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		ips = append(ips, ip)
	}
	c.JSON(http.StatusOK, ips)
}

func getProgress(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"progress": progress})
}

func getEvents(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parâmetro 'ip' é obrigatório"})
		return
	}
	protocol := c.Query("protocol")
	var rows *sql.Rows
	var err error

	if protocol != "" {
		rows, err = db.Query("SELECT id, ip, protocol, timestamp FROM events WHERE ip = ? AND protocol = ? ORDER BY timestamp ASC", ip, protocol)
	} else {
		rows, err = db.Query("SELECT id, ip, protocol, timestamp FROM events WHERE ip = ? ORDER BY timestamp ASC", ip)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro na consulta"})
		return
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var id int
		var ip string
		var protocol string
		var timestamp time.Time
		rows.Scan(&id, &ip, &protocol, &timestamp)
		events = append(events, map[string]interface{}{
			"id":        id,
			"ip":        ip,
			"protocol":  protocol,
			"timestamp": timestamp.Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, events)
}

