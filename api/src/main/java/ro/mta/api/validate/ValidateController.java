package ro.mta.api.validate;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "api/v1/validate")
public class ValidateController {

    @GetMapping
    public String getValidation() {
        return "Validate Controller";
    }
}
