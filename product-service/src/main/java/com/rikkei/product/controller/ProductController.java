package com.rikkei.product.controller;

import com.rikkei.product.dto.ProductDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST controller exposing product endpoints with role-based access control.
 *
 * Endpoint summary:
 *   GET  /api/products        - accessible to any authenticated user (USER or ADMIN)
 *   DELETE /api/products/{id} - accessible to ADMIN only
 */
@RestController
@RequestMapping("/api/products")
public class ProductController {

    // Static in-memory product catalog for demonstration purposes
    private static final List<ProductDTO> PRODUCTS = List.of(
            new ProductDTO(1L, "Laptop Dell XPS 15", 35_990_000.0),
            new ProductDTO(2L, "iPhone 16 Pro Max", 29_990_000.0),
            new ProductDTO(3L, "Samsung Galaxy S25 Ultra", 27_490_000.0)
    );

    /**
     * Returns the full product catalog.
     * Accessible by any authenticated user (USER or ADMIN role).
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<ProductDTO>> getAllProducts() {
        return ResponseEntity.ok(PRODUCTS);
    }

    /**
     * Deletes a product by ID.
     * Accessible by ADMIN role only.
     * (Static demo — does not modify the in-memory list.)
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deleteProduct(@PathVariable Long id) {
        return ResponseEntity.ok("Product " + id + " deleted successfully");
    }
}
