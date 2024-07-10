package gmailauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

type ScopeType string

const (
	READONLY                        ScopeType = gmail.GmailReadonlyScope
	ADDONS_CURRENT_ACTION_COMPOSE   ScopeType = gmail.GmailAddonsCurrentActionComposeScope
	ADDONS_CURRENT_MESSAGE_ACTION   ScopeType = gmail.GmailAddonsCurrentMessageActionScope
	ADDONS_CURRENT_MESSAGE_METADATA ScopeType = gmail.GmailAddonsCurrentMessageMetadataScope
	ADDONS_CURRENT_MESSAGE_READONLY ScopeType = gmail.GmailAddonsCurrentMessageReadonlyScope
	COMPOSE                         ScopeType = gmail.GmailComposeScope
	INSERT                          ScopeType = gmail.GmailInsertScope
	LABELS                          ScopeType = gmail.GmailLabelsScope
	METADATA                        ScopeType = gmail.GmailMetadataScope
	MODIFY                          ScopeType = gmail.GmailModifyScope
	SEND                            ScopeType = gmail.GmailSendScope
	SETTINGS_BASIC                  ScopeType = gmail.GmailSettingsBasicScope
	SETTINGS_SHARING                ScopeType = gmail.GmailSettingsSharingScope
	MAIL_GOOGLE_COM                 ScopeType = gmail.MailGoogleComScope
)

func getClient(config *oauth2.Config) (*http.Client, error) {
	file := "gmail-token.json"
	token, err := getTokenFromFile(file)
	if err != nil {
		token, err = getTokenFromWeb(config)
		if err != nil {
			return nil, err
		}

		err = saveToken(file, token)
		if err != nil {
			return nil, err
		}
	}

	return config.Client(context.Background(), token), nil
}

func getTokenFromWeb(config *oauth2.Config) (*oauth2.Token, error) {
	authUrl := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type authorization code: \n%v\n", authUrl)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		return nil, fmt.Errorf("unable to read authorization code: %v", err)
	}

	token, err := config.Exchange(context.Background(), authCode)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve token from web: %v", err)
	}

	return token, nil
}

func getTokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	token := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(token)

	return token, err
}

func saveToken(path string, token *oauth2.Token) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("unable to save oauth token: %v", err)
	}
	defer f.Close()

	json.NewEncoder(f).Encode(token)

	return nil
}

func AuthUser(file string, scope ScopeType) (*gmail.Service, error) {
	ctx := context.Background()
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read client secrete file: %v", err)
	}

	config, err := google.ConfigFromJSON(b, string(scope))
	if err != nil {
		return nil, fmt.Errorf("unable to parse client secrete file: %v", err)
	}

	client, err := getClient(config)
	if err != nil {
		return nil, fmt.Errorf("unable to get client: %v", err)
	}

	service, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("unable to create new service: %v", err)
	}

	return service, nil
}
