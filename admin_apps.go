package vpnless

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

const (
	labelHomepageGroup       = "homepage.group"
	labelHomepageName        = "homepage.name"
	labelHomepageIcon        = "homepage.icon"
	labelHomepageHref        = "homepage.href"
	labelHomepageDescription = "homepage.description"
	labelHomepageWeight      = "homepage.weight"
	homarrIconsPNGBase       = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/"
	homarrIconsSVGBase       = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/"
	// Default matches Get Homepage discovered services (weight 0 = primary sort by name when tied).
	defaultHomepageWeight = 0
)

// adminAppJSON is one tile built from Docker labels (Get Homepage style).
type adminAppJSON struct {
	Name                 string `json:"name"`
	Href                 string `json:"href"`
	IconURL              string `json:"icon_url,omitempty"`
	Description          string `json:"description,omitempty"`
	Container            string `json:"container_id,omitempty"`
	Weight               int    `json:"weight,omitempty"`                 // homepage.weight; lower = earlier within group (default 0, same as Get Homepage).
	ContainerCreatedUnix int64  `json:"container_created_unix,omitempty"` // Docker container Created (unix); used for Overview “new” window.
}

type adminAppGroupJSON struct {
	Name string         `json:"name"`
	Apps []adminAppJSON `json:"apps"`
}

// handleAppsList returns running containers with homepage.* labels as grouped JSON.
func (m *DeviceAuth) handleAppsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	groups, warn := m.collectDockerApps(r.Context())
	payload := map[string]any{"groups": groups}
	if warn != "" {
		payload["warning"] = warn
	}
	writeAdminJSON(w, payload)
}

func (m *DeviceAuth) collectDockerApps(ctx context.Context) ([]adminAppGroupJSON, string) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	opts := []client.Opt{client.WithAPIVersionNegotiation()}
	if strings.TrimSpace(m.DockerHost) != "" {
		opts = append(opts, client.WithHost(strings.TrimSpace(m.DockerHost)))
	} else {
		opts = append(opts, client.FromEnv)
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Sprintf("docker client: %v", err)
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, containertypes.ListOptions{})
	if err != nil {
		return nil, fmt.Sprintf("docker list: %v", err)
	}

	type groupAcc struct {
		displayName string
		apps        []adminAppJSON
	}
	byNorm := make(map[string]*groupAcc)

	for _, c := range containers {
		if !strings.EqualFold(c.State, "running") {
			continue
		}
		labels := c.Labels
		if labels == nil {
			continue
		}
		name := strings.TrimSpace(labels[labelHomepageName])
		href := strings.TrimSpace(labels[labelHomepageHref])
		if name == "" && href == "" {
			continue
		}
		if name == "" {
			name = primaryContainerName(c.Names)
			if name == "" {
				name = "Service"
			}
		}
		group := strings.TrimSpace(labels[labelHomepageGroup])
		if group == "" {
			group = "Services"
		}
		rawIcon := strings.TrimSpace(labels[labelHomepageIcon])
		desc := strings.TrimSpace(labels[labelHomepageDescription])
		appW := parseIntLabel(labels, labelHomepageWeight, defaultHomepageWeight)

		norm := strings.ToLower(group)
		if byNorm[norm] == nil {
			byNorm[norm] = &groupAcc{displayName: group, apps: nil}
		}
		cid := c.ID
		if len(cid) > 12 {
			cid = cid[:12]
		}
		byNorm[norm].apps = append(byNorm[norm].apps, adminAppJSON{
			Name:                 name,
			Href:                 href,
			IconURL:              resolveHomarrIconURL(rawIcon),
			Description:          desc,
			Container:            cid,
			Weight:               appW,
			ContainerCreatedUnix: c.Created,
		})
	}

	if len(byNorm) == 0 {
		return []adminAppGroupJSON{}, ""
	}

	type groupKey struct {
		norm string
		ga   *groupAcc
	}
	gkeys := make([]groupKey, 0, len(byNorm))
	for k, ga := range byNorm {
		gkeys = append(gkeys, groupKey{norm: k, ga: ga})
	}
	sort.SliceStable(gkeys, func(i, j int) bool {
		return strings.ToLower(gkeys[i].ga.displayName) < strings.ToLower(gkeys[j].ga.displayName)
	})

	out := make([]adminAppGroupJSON, 0, len(gkeys))
	for _, gk := range gkeys {
		ga := gk.ga
		sort.SliceStable(ga.apps, func(i, j int) bool {
			if ga.apps[i].Weight != ga.apps[j].Weight {
				return ga.apps[i].Weight < ga.apps[j].Weight
			}
			return strings.ToLower(ga.apps[i].Name) < strings.ToLower(ga.apps[j].Name)
		})
		out = append(out, adminAppGroupJSON{Name: ga.displayName, Apps: ga.apps})
	}
	return out, ""
}

func parseIntLabel(labels map[string]string, key string, def int) int {
	if labels == nil {
		return def
	}
	s := strings.TrimSpace(labels[key])
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func primaryContainerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	n := names[0]
	n = strings.TrimPrefix(n, "/")
	return n
}

func resolveHomarrIconURL(icon string) string {
	icon = strings.TrimSpace(icon)
	if icon == "" {
		return ""
	}
	if strings.Contains(icon, "://") {
		return icon
	}
	lower := strings.ToLower(icon)
	if strings.HasPrefix(icon, "/") {
		return icon
	}
	if strings.HasSuffix(lower, ".svg") {
		base := path.Base(icon)
		return homarrIconsSVGBase + base
	}
	if strings.HasSuffix(lower, ".png") {
		return homarrIconsPNGBase + path.Base(icon)
	}
	// Short name like "portainer"
	return homarrIconsPNGBase + icon + ".png"
}
