
from .default import GlobalSchedulingAlgorithm
from .limitedOpen import LimitedOpenSchedulingAlgorithm

TicketSchedulingAlgorithms = {
    GlobalSchedulingAlgorithm.__name__: GlobalSchedulingAlgorithm(),
    LimitedOpenSchedulingAlgorithm.__name__: LimitedOpenSchedulingAlgorithm(),
}
