package pl.mimuw.carrentalback.controllers;

import lombok.Data;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.mimuw.carrentalback.models.User;
import pl.mimuw.carrentalback.payload.response.MessageResponse;
import pl.mimuw.carrentalback.payload.response.ProfileResponse;
import pl.mimuw.carrentalback.services.ProfileInfoService;

@Data
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("/api/profile")
public class ProfileController {
    private final ProfileInfoService profileService;

    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> profileInfo() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        User user = profileService.getUserInfo(auth.getName());
        return ResponseEntity.ok(new ProfileResponse(user));
    }
}
