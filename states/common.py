start_time = None

# Batch of the current period
current_batch = None

# Fix-sized queue, holds the number of incoming packets in each batch
batches_queue = None

# Fix-sized queue, holds variance of rate packets in each batch
rate_queue = None

# probability critics for length of batch
BATCH_LEN_EPSILON = 0.01

# probability critics for rate in batch
RATE_EPSILON = 0.01

# Time period for each batch
BATCH_PERIOD = 30

# Size of batches_count
PERIODS_IN_HOUR = None

PERIODS_IN_DAY = None

# Number of required batches before checking the traffic
TIME_TO_PARAMETERIZE = 24 * 60 * 60

TIME_TO_LEARN = 24 * 60 * 60 * 14

# Days backwards to remember batches
DAYS_REMEMBER = 30

# Number of batches to remember
NUMBER_OF_BATCHES_TO_REMEMBER = None