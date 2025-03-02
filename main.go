package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var db *sql.DB

var progress float64 = 0
var totalPackets int = 0

func main() {
	var err error
	db, err = sql.Open("sqlite3", "data.db")
	if err != nil {
		log.Fatal(err)
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

	fmt.Println("Servidor iniciado em http://localhost:8080")
	r.Run(":8080")
}

func createTable() {
	query := `CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT,
		protocol TEXT,
		timestamp DATETIME
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
	rows, err := db.Query("SELECT strftime('%Y-%m-%d %H:%M', timestamp) as minute, COUNT(*) as count FROM events WHERE ip = ? GROUP BY minute ORDER BY minute ASC", ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro na consulta"})
		return
	}
	defer rows.Close()

	var timeline []map[string]interface{}
	for rows.Next() {
		var minute string
		var count int
		rows.Scan(&minute, &count)
		timeline = append(timeline, map[string]interface{}{"minute": minute, "count": count})
	}
	c.JSON(http.StatusOK, timeline)
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
