package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/gtuk/discordwebhook"
	"github.com/joho/godotenv"
	"github.com/likexian/whois"
	"github.com/sirupsen/logrus"
)

func main() {
	_ = godotenv.Load()

	workDir := os.Getenv("WORK_DIR")
	if workDir == "" {
		workDir = "/tmp/whois-watch"
	}
	domains := strings.Split(os.Getenv("WATCH_DOMAINS"), " ")

	err := os.MkdirAll(workDir, 0755)
	if err != nil {
		logrus.Fatalf("create work dir error: %v", err)
	}
	err = os.MkdirAll(path.Join(workDir, "history"), 0755)
	if err != nil {
		logrus.Fatalf("create history work dir error: %v", err)
	}

	for {
		err = run(workDir, domains)

		if err != nil {
			logrus.Errorf("run error: %v", err)

			// try to send error message to discord
			content := "# Error occurred"
			if os.Getenv("NOTIFY_DISCORD_USER_ID") != "" {
				content += "\n\n<@" + os.Getenv("NOTIFY_DISCORD_USER_ID") + ">"
			}
			content += "\n\n```\n" + err.Error() + "```"
			message := discordwebhook.Message{
				Content: &content,
			}

			err = discordwebhook.SendMessage(os.Getenv("NOTIFY_DISCORD_WEBHOOK"), message)
			if err != nil {
				logrus.Fatalf("send error message to discord error: %v", err)
			}
		}

		time.Sleep(12 * time.Hour)
	}
}

func run(workDir string, domains []string) error {
	for _, domain := range domains {
		log := logrus.WithField("domain", domain)

		result, err := whoisDomain(domain)
		if err != nil {
			return err
		}

		file, err := os.ReadFile(path.Join(workDir, fmt.Sprintf("%s.txt", domain)))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}

			log.Infof("file not exist, create new file")
			err = os.WriteFile(path.Join(workDir, fmt.Sprintf("%s.txt", domain)), []byte(result), 0644)
			if err != nil {
				return err
			}
			continue
		}
		
		err = os.WriteFile(path.Join(workDir, fmt.Sprintf("%s.txt", domain)), []byte(result), 0644)
		if err != nil {
			return err
		}

		diff, err := diffLineByLine(string(file), result)
		if err != nil {
			return err
		}

		if len(diff) == 0 {
			log.Infof("whois result is same as before")
			continue
		}

		log.Infof("whois result is different from before:")
		for _, line := range strings.Split(diff, "\n") {
			log.Infof("   %s", line)
		}

		content := "# Domain `" + domain + "` has been changed"
		if os.Getenv("NOTIFY_DISCORD_USER_ID") != "" {
			content += "\n\n<@" + os.Getenv("NOTIFY_DISCORD_USER_ID") + ">"
		}
		content += "\n\n```diff\n" + diff + "```"
		message := discordwebhook.Message{
			Content: &content,
		}

		err = discordwebhook.SendMessage(os.Getenv("NOTIFY_DISCORD_WEBHOOK"), message)
		if err != nil {
			return err
		}

		err = os.WriteFile(path.Join(workDir, "history", fmt.Sprintf("%s.%d.diff", domain, time.Now().Unix())), []byte(diff), 0644)
		if err != nil {
			log.Errorf("write diff file error: %v", err)
		}
	}

	return nil
}

func diffLineByLine(from, to string) (string, error) {
	workDir, err := os.MkdirTemp("", "diff")
	defer os.RemoveAll(workDir)
	if err != nil {
		return "", err
	}

	fromFile := path.Join(workDir, "from.txt")
	toFile := path.Join(workDir, "to.txt")

	err = os.WriteFile(fromFile, []byte(from), 0644)
	if err != nil {
		return "", err
	}
	err = os.WriteFile(toFile, []byte(to), 0644)
	if err != nil {
		return "", err
	}

	cmd := exec.Command("diff", fromFile, toFile)
	out, err := cmd.Output()
	if err != nil && cmd.ProcessState.ExitCode() != 1 {
		return "", err
	}

	return string(out), nil
}

func whoisDomain(domain string) (string, error) {
	result, err := whois.Whois(domain)
	if err != nil {
		return "", err
	}

	lines := strings.Split(result, "\n")
	result = ""
	for _, line := range lines {
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, ">>>") || strings.Contains(line, "WHOIS lookup made on ") {
			continue
		}
		result += line + "\n"
	}

	return result, nil
}
