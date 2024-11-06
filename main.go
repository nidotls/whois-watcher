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
	err = os.MkdirAll(path.Join(workDir, "diff"), 0755)
	if err != nil {
		logrus.Fatalf("create diff work dir error: %v", err)
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
			errStr := err.Error()
			if len(errStr) > 1800 {
				logrus.Warnf("error message is too long, truncate it")
				errStr = errStr[:1800]
			}
			content += "\n\n```\n" + errStr + "```"
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
			return fmt.Errorf("whois error on domain %s: %v", domain, err)
		}

		file, err := os.ReadFile(path.Join(workDir, fmt.Sprintf("%s.txt", domain)))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("read file error on domain %s: %v", domain, err)
			}

			log.Infof("file not exist, create new file")
			err = os.WriteFile(path.Join(workDir, fmt.Sprintf("%s.txt", domain)), []byte(result), 0644)
			if err != nil {
				return fmt.Errorf("write file error on domain %s: %v", domain, err)
			}

			err = os.WriteFile(path.Join(workDir, "history", fmt.Sprintf("%s.%d.txt", domain, time.Now().Unix())), []byte(result), 0644)
			if err != nil {
				log.Errorf("write history file error on domain %s: %v", domain, err)
			}
			continue
		}

		if _, err := os.Stat(path.Join(workDir, fmt.Sprintf("%s.txt", domain))); os.IsNotExist(err) {
			err = os.WriteFile(path.Join(workDir, "history", fmt.Sprintf("%s.%d.txt", domain, time.Now().Unix())), []byte(result), 0644)
			if err != nil {
				log.Errorf("write history file error on domain %s: %v", domain, err)
			}
		}

		err = os.WriteFile(path.Join(workDir, fmt.Sprintf("%s.txt", domain)), []byte(result), 0644)
		if err != nil {
			return fmt.Errorf("write file error on domain %s: %v", domain, err)
		}

		diff, err := diffLineByLine(string(file), result)
		if err != nil {
			return fmt.Errorf("diff error on domain %s: %v", domain, err)
		}

		if len(diff) == 0 {
			log.Debugf("whois result is same as before")
			continue
		}

		log.Infof("has been changed", domain)

		log.Debugf("whois result is different from before:")
		for _, line := range strings.Split(diff, "\n") {
			log.Debugf("   %s", line)
		}

		err = os.WriteFile(path.Join(workDir, "history", fmt.Sprintf("%s.%d.txt", domain, time.Now().Unix())), []byte(result), 0644)
		if err != nil {
			log.Errorf("write history file error: %v", err)
		}
		err = os.WriteFile(path.Join(workDir, "diff", fmt.Sprintf("%s.%d.diff", domain, time.Now().Unix())), []byte(diff), 0644)
		if err != nil {
			log.Errorf("write diff file error: %v", err)
		}

		messages := generateMessagesFromDiff(domain, diff)

		var errs []error
		for _, message := range messages {
			err = discordwebhook.SendMessage(os.Getenv("NOTIFY_DISCORD_WEBHOOK"), message)
			if err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("send discord message error: %v", errs)
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

func generateMessagesFromDiff(domain string, diff string) []discordwebhook.Message {
	header := "# Domain `" + domain + "` has been changed"
	if os.Getenv("NOTIFY_DISCORD_USER_ID") != "" {
		header += "\n\n<@" + os.Getenv("NOTIFY_DISCORD_USER_ID") + ">"
	}
	header += "\n\n"

	lines := strings.Split(diff, "\n")
	var lineBlocks []string
	currentLineBlock := ""
	for _, line := range lines {
		if len(lineBlocks) == 0 && len(header)+len(currentLineBlock)+len(line) > 1950 {
			lineBlocks = append(lineBlocks, currentLineBlock)
			currentLineBlock = ""
		}

		if len(lineBlocks) > 0 && len(currentLineBlock)+len(line) > 1950 {
			lineBlocks = append(lineBlocks, currentLineBlock)
			currentLineBlock = ""
		}

		if len(currentLineBlock) > 0 {
			currentLineBlock += "\n"
		}
		currentLineBlock += line
	}
	if len(currentLineBlock) > 0 {
		lineBlocks = append(lineBlocks, currentLineBlock)
	}

	var messages []discordwebhook.Message

	for i, lineBlock := range lineBlocks {
		content := ""
		if i == 0 {
			content = header
			content += "```diff\n" + lineBlock + "\n```"
		} else {
			content = "```diff\n" + lineBlock + "\n```"
		}

		messages = append(messages, discordwebhook.Message{
			Content: &content,
		})
	}

	return messages
}
