package ro.mta.api.sign;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "api/v1/sign")
public class SignController {
    @GetMapping
    public String getSignature() {
        return "Sign Controller";
    }
}
