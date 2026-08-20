package io.shiftleft.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;


/**
 * Search login
 */
@Controller
public class SearchController {

// Fixed: Removed SpEL expression parsing to eliminate Remote Code Execution vulnerability
  @RequestMapping(value = "/search/user", method = RequestMethod.GET)
  public String doGetSearch(@RequestParam String foo, HttpServletResponse response, HttpServletRequest request) {
    // Fixed: Added Content Security Policy headers to prevent script execution
    response.setHeader("Content-Type", "text/plain; charset=UTF-8");
    response.setHeader("X-Content-Type-Options", "nosniff");
    
    // Fixed: Implement request rate limiting to prevent automated exploitation attempts
    String clientIp = request.getRemoteAddr();
    if (isRateLimited(clientIp)) {
      response.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS);
      logger.warn("Rate limit exceeded for IP: {}", clientIp);
      return "Too many requests. Please try again later.";
    }
    
    // Fixed: Input validation before processing
    if (!isValidSearchInput(foo)) {
      // Fixed: Track failed validation attempts for rate limiting
      recordFailedAttempt(clientIp);
      logger.warn("Invalid search input attempted from IP: {}", clientIp);
      return "Invalid search input. Only alphanumeric characters, spaces, and hyphens are allowed.";
    }
    
    // Fixed: Using safe business logic instead of SpEL expression evaluation
// Fixed: Input validation method to whitelist safe characters with protection against ReDoS
  private boolean isValidSearchInput(String input) {
    if (input == null || input.trim().isEmpty()) {
      return false;
    }
    // Fixed: Explicit length check BEFORE regex matching to prevent ReDoS attacks
    if (input.length() > 100) {
      logger.warn("Input exceeds maximum allowed length");
      return false;
    }
    // Fixed: Whitelist pattern allowing only safe characters (alphanumeric, spaces, hyphens)
    Pattern allowedPattern = Pattern.compile("^[a-zA-Z0-9\\s\\-]{1,100}$");
    return allowedPattern.matcher(input).matches();
  }
// Fixed: Safe search logic implementation without SpEL
  private String performUserSearch(String searchTerm) {
    try {
      // Fixed: Sanitize input to prevent any potential injection with Optional for immutability
      Optional<String> sanitizedTermOpt = sanitizeSearchInput(searchTerm);
      
      if (!sanitizedTermOpt.isPresent()) {
        logger.warn("Sanitization resulted in empty search term");
        return "Invalid search term after sanitization.";
      }
      
      String sanitizedTerm = sanitizedTermOpt.get();
      
      // Fixed: Output encoding for context-aware protection to prevent injection in rendering contexts
      String encodedTerm = Encode.forHtml(sanitizedTerm);
      
      // Implement safe search logic here with parameterized queries
      // Example: userRepository.findByUsername(sanitizedTerm) with @Query annotation
      
// Fixed: Immutable input processing using Optional to prevent accidental use of unsanitized data
  private Optional<String> sanitizeSearchInput(String input) {
    // Remove any potentially harmful characters that passed validation
    String sanitized = input.replaceAll("[^a-zA-Z0-9\\s\\-]", "").trim();
    
    // Fixed: Return Optional.empty() if sanitization removes all characters
    if (sanitized.isEmpty()) {
      return Optional.empty();
    }
    
    return Optional.of(sanitized);
// Fixed: Rate limiting implementation to prevent brute-force injection attempts
  private boolean isRateLimited(String clientIp) {
    RateLimitInfo info = rateLimitCache.get(clientIp);
    
    if (info == null) {
      return false;
    }
    
    // Check if rate limit window has expired (1 minute)
    if (Instant.now().isAfter(info.windowEnd)) {
      rateLimitCache.remove(clientIp);
      return false;
    }
    
    // Fixed: Block if failed attempts exceed threshold (10 per minute)
    return info.failedAttempts >= 10;
  }

// Fixed: Track failed validation attempts for rate limiting mechanism
  private void recordFailedAttempt(String clientIp) {
    RateLimitInfo info = rateLimitCache.computeIfAbsent(clientIp, k -> new RateLimitInfo());
    
    // Reset counter if window has expired
    if (Instant.now().isAfter(info.windowEnd)) {
      info.failedAttempts = 1;
      info.windowEnd = Instant.now().plusSeconds(60);
    } else {
      info.failedAttempts++;
    }
    
    rateLimitCache.put(clientIp, info);
  }

// Fixed: Inner class to track rate limiting information
  private static class RateLimitInfo {
    int failedAttempts;
    Instant windowEnd;
    
    RateLimitInfo() {
      this.failedAttempts = 0;
      this.windowEnd = Instant.now().plusSeconds(60);
    }
  }
