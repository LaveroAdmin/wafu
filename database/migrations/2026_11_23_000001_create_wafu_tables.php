<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function getConnection()
    {
        return config('admin.database.connection') ?: config('database.default');
    }

    public function up(): void
    {
        $connection = $this->getConnection();

        if (!Schema::connection($connection)->hasTable('wafu_events')) {
            Schema::connection($connection)->create('wafu_events', function (Blueprint $table) {
                $table->id();
                $table->string('ip', 45)->index();
                $table->string('method', 10)->index();
                $table->text('uri');
                $table->string('module', 50)->index();
                $table->string('action', 20)->default('block');
                $table->string('reason', 255)->nullable();
                $table->integer('status_code')->default(403);
                $table->text('user_agent')->nullable();
                $table->longText('payload')->nullable();
                $table->boolean('blocked')->default(true)->index();
                $table->timestamps();
            });
        }

        if (!Schema::connection($connection)->hasTable('wafu_blocks')) {
            Schema::connection($connection)->create('wafu_blocks', function (Blueprint $table) {
                $table->id();
                $table->string('ip', 45)->unique();
                $table->string('reason', 255)->nullable();
                $table->boolean('is_blocked')->default(true)->index();
                $table->timestamp('blocked_at')->nullable();
                $table->timestamp('unblocked_at')->nullable();
                $table->timestamps();
            });
        }

        if (!Schema::connection($connection)->hasTable('wafu_settings')) {
            Schema::connection($connection)->create('wafu_settings', function (Blueprint $table) {
                $table->id();
                $table->string('key', 100)->unique();
                $table->longText('value')->nullable();
                $table->timestamps();
            });
        }
    }

    public function down(): void
    {
        $connection = $this->getConnection();
        Schema::connection($connection)->dropIfExists('wafu_events');
        Schema::connection($connection)->dropIfExists('wafu_blocks');
        Schema::connection($connection)->dropIfExists('wafu_settings');
    }
};
