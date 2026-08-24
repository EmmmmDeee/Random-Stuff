// ============================================================================
// LLM ERROR TYPES
// ============================================================================

#[derive(Debug)]
pub enum LLMError {
    Network(String),
    InvalidResponse(String),
    ParseError(String),
    ModelNotFound(String),
    Timeout(String),
    Configuration(String),
    ModelLoading(String),
}

impl std::fmt::Display for LLMError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LLMError::Network(msg) => write!(f, "Network error: {}", msg),
            LLMError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            LLMError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            LLMError::ModelNotFound(msg) => write!(f, "Model not found: {}", msg),
            LLMError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            LLMError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            LLMError::ModelLoading(msg) => write!(f, "Model loading error: {}", msg),
        }
    }
}

impl std::error::Error for LLMError {}

pub type LLMResult<T> = Result<T, LLMError>;
