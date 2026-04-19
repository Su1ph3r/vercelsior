package reporter

import (
	"encoding/json"
	"os"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

func WriteJSON(result *models.ScanResult, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
