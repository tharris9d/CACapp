import { Component, EventEmitter, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-pin-entry',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './pin-entry.component.html',
  styleUrl: './pin-entry.component.css'
})
export class PinEntryComponent {
  pin: string = '';
  showPin: boolean = false;
  errorMessage: string = '';

  @Output() pinSubmitted = new EventEmitter<string>();
  @Output() cancelled = new EventEmitter<void>();

  onSubmit(): void {
    if (!this.pin || this.pin.length < 4) {
      this.errorMessage = 'PIN must be at least 4 characters';
      return;
    }

    this.errorMessage = '';
    this.pinSubmitted.emit(this.pin);
  }

  onCancel(): void {
    this.pin = '';
    this.errorMessage = '';
    this.cancelled.emit();
  }

  toggleShowPin(): void {
    this.showPin = !this.showPin;
  }

  onKeyDown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      this.onSubmit();
    } else if (event.key === 'Escape') {
      this.onCancel();
    }
  }
}

