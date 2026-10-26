package com.rikkei.product.dto;

/**
 * Immutable data transfer object representing a product.
 */
public record ProductDTO(Long id, String name, double price) {}
