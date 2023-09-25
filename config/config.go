package config

import (
	"math"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/crtsh/cert_processor/logger"

	"github.com/spf13/viper"

	"go.uber.org/zap"
)

type config struct {
	CertWatchDB struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
	}
	Processor struct {
		MaxBatchSize             int           `mapstructure:"maxBatchSize"`
		BatchFrequency           time.Duration `mapstructure:"batchFrequency"`
		RetryAfterErrorFrequency time.Duration `mapstructure:"retryAfterErrorFrequency"`
	}
	Expirer struct {
		BatchFrequency           time.Duration `mapstructure:"batchFrequency"`
		RetryAfterErrorFrequency time.Duration `mapstructure:"retryAfterErrorFrequency"`
	}
	Server struct {
		MonitoringPort int `mapstructure:"monitoringPort"`
	}
	Logging struct {
		IsDevelopment      bool `mapstructure:"isDevelopment"`
		SamplingInitial    int  `mapstructure:"samplingInitial"`
		SamplingThereafter int  `mapstructure:"samplingThereafter"`
	}
}

var Config config
var GitCommit, GitBranch, GitState, GitSummary, BuildDate, Version string // Automatically populated if built by https://github.com/ahmetb/govvv.

func init() {
	if err := initViper(); err != nil {
		panic(err)
	} else if err = logger.InitLogger(Config.Logging.IsDevelopment, Config.Logging.SamplingInitial, Config.Logging.SamplingThereafter); err != nil {
		panic(err)
	}

	// Log build information, if the application was built with govvv.
	if BuildDate != "" {
		logger.Logger.Info(
			"Build information",
			zap.String("git_commit", GitCommit),
			zap.String("git_branch", GitBranch),
			zap.String("git_state", GitState),
			zap.String("git_summary", GitSummary),
			zap.String("build_date", BuildDate),
			zap.String("version", Version),
		)
	}

	// Log RLIMIT_NOFILE soft and hard limits.
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		logger.Logger.Error(
			"Getrlimit(RLIMIT_NOFILE) error",
			zap.Error(err),
		)
	} else {
		logger.Logger.Info(
			"Resource limits",
			zap.Uint64("rlimit_nofile_soft", rlimit.Cur),
			zap.Uint64("rlimit_nofile_hard", rlimit.Max),
			zap.String("gomemlimit", os.Getenv("GOMEMLIMIT")),
		)
	}
}

func initViper() error {
	// Import config file values from least to most specific.
	viper.SetConfigName("config.yaml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/config")  // /config/config.yaml
	viper.AddConfigPath("./config") // ./config/config.yaml
	viper.AddConfigPath(".")        // ./config.yaml

	// Setup Viper to also look at environment variables.
	viper.SetEnvPrefix("certprocessor")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // Fix for nested struct references (https://github.com/spf13/viper/issues/160#issuecomment-189551355).
	viper.AutomaticEnv()

	// Enable environment variables to be unmarshalled to slices (https://stackoverflow.com/a/43241844).
	viper.SetTypeByDefaultValue(true)

	// Set defaults for all values in-order to use env config for all options
	viper.SetDefault("certwatchdb.host", "/var/run/postgresql")
	viper.SetDefault("certwatchdb.port", 5432)
	viper.SetDefault("certwatchdb.user", "certwatch")
	viper.SetDefault("certwatchdb.password", "")
	viper.SetDefault("processor.maxBatchSize", 10000)
	viper.SetDefault("processor.batchFrequency", 10*time.Second)
	viper.SetDefault("processor.retryAfterErrorFrequency", time.Minute)
	viper.SetDefault("expirer.batchFrequency", time.Second)
	viper.SetDefault("expirer.retryAfterErrorFrequency", time.Minute)
	viper.SetDefault("server.monitoringPort", 8081)
	viper.SetDefault("logging.isDevelopment", false)
	viper.SetDefault("logging.samplingInitial", math.MaxInt)    // When both of these are set to MaxInt, sampling is disabled.
	viper.SetDefault("logging.samplingThereafter", math.MaxInt) // See https://pkg.go.dev/go.uber.org/zap/zapcore#NewSamplerWithOptions for more information.

	// Render results to Config Struct.
	_ = viper.ReadInConfig() // Ignore errors, because we also support reading config from environment variables.
	return viper.Unmarshal(&Config)
}
