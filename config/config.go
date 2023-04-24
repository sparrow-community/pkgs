package config

import (
	"encoding/json"
	"fmt"
	"go-micro.dev/v4/config"
	"go-micro.dev/v4/config/source"
)

type Server struct {
	Id        string                 `json:"id"`
	Name      string                 `json:"name"`
	Address   string                 `json:"address"`
	Advertise string                 `json:"advertise"`
	Metadata  map[string]interface{} `json:"metadata"`
	Version   string                 `json:"version"`
}

type MicroConfig struct {
	vals map[string]any
	opts Options
}

// New micro config read & merge variables (default < remote < local < env < cli)
func New(opt ...Option) (*MicroConfig, error) {
	opts := Options{}
	for _, o := range opt {
		o(&opts)
	}

	mc := &MicroConfig{
		opts: opts,
		vals: map[string]any{},
	}

	// default cli source
	defaultSource := cliSource(opts.serverName, opts.flags...)
	if err := config.Load(defaultSource); err != nil {
		return nil, err
	}

	if err := config.Scan(&mc.vals); err != nil {
		return nil, err
	}

	// default value
	if mc.opts.defaultVals != nil {
		mc.vals = mergeMaps(mc.vals, mc.opts.defaultVals)
	}

	// default local file source
	defaultLocalFileSource := LocalFileSource(fmt.Sprintf("%s.json", opts.serverName))
	if defaultLocalFileSource != nil {
		opts.sources = append(opts.sources, defaultLocalFileSource)
	}

	if c, ok := mc.vals["config"]; ok && len(c.(string)) > 0 {
		opts.sources = append(opts.sources, LocalFileSource(c.(string)))
	}

	var err error
	mc.vals, err = mergeSource(mc.vals, opts.sources)
	if err != nil {
		return nil, err
	}

	return mc, nil
}

func (m *MicroConfig) Scan(v interface{}) error {
	vals, err := json.Marshal(m.vals)
	if err != nil {
		return err
	}
	err = json.Unmarshal(vals, v)
	if err != nil {
		return err
	}
	return nil
}

func mergeSource(vals map[string]any, sources []source.Source) (map[string]any, error) {
	for _, s := range sources {
		conf, _ := config.NewConfig()
		if err := conf.Load(s); err != nil {
			return nil, err
		}
		sourceMap := map[string]any{}
		if err := conf.Scan(&sourceMap); err != nil {
			return nil, err
		}
		vals = mergeMaps(vals, sourceMap)
	}
	return vals, nil
}

func mergeMaps(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a))
	for k, v := range a {
		if isEmpty(out[k]) {
			out[k] = v
		}
	}
	for k, v := range b {
		if v, ok := v.(map[string]any); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]any); ok {
					out[k] = mergeMaps(bv, v)
					continue
				}
			}
		}
		if isEmpty(out[k]) {
			out[k] = v
		}
	}
	return out
}

func isEmpty(i any) bool {
	if i == nil {
		return true
	}

	switch v := i.(type) {
	case string:
		return len(v) == 0
	default:
		return false
	}
}
