import { Component, EventEmitter, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-password-prompt',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './password-prompt.component.html',
  styleUrl: './password-prompt.component.css'
})
export class PasswordPromptComponent {
  password = '';
  showPassword = false;

  @Output() passwordSubmitted = new EventEmitter<string>();
  @Output() cancelled = new EventEmitter<void>();

  onSubmit(): void {
    if (this.password.trim()) {
      this.passwordSubmitted.emit(this.password);
      this.password = '';
    }
  }

  onCancel(): void {
    this.password = '';
    this.cancelled.emit();
  }

  togglePasswordVisibility(): void {
    this.showPassword = !this.showPassword;
  }
}


